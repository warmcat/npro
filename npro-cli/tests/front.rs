//! The front over real sockets: a directory served by npro-files through
//! the runner, its reads done by the adapter's workers, a 404 document,
//! a 304, a HEAD, a request passed to an origin by npro-proxy and its
//! answer passed back, an origin that is not there, and a policy naming
//! a service that is not built in.

#![expect(
    unused_crate_dependencies,
    reason = "an integration test sees all of its crate's dependencies; this one uses npro-cli, npro-core, npro-files, npro-io and npro-ss"
)]

// held to clippy's rules for tests
#[cfg(test)]
mod front {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::path::PathBuf;
    use std::thread;

    use core::time::Duration;

    use npro_cgi::Script;
    use npro_cli::front::{App, Front, Logs, Service, Services, act, check};
    use npro_cli::runner::{Streams, bind};
    use npro_files::{Cache, Intermediaries, Mount, Revalidate};
    use npro_h1::server::Config;
    use npro_io::threads::{Stop, Workers};
    use npro_proxy::Upstream;
    use npro_ss::id::ListenerId;
    use npro_ss::policy::{Listener, Match, Route, Tls, Vhost, Ws};

    /// A directory of files to serve, `name`'s own: its path, leaked for
    /// the policy.
    fn www(name: &str) -> &'static str {
        let dir: PathBuf =
            std::env::temp_dir().join(format!("npro-front-{name}-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("index.html"), b"<html>front</html>").unwrap();
        std::fs::write(dir.join("sub/index.html"), b"<html>sub</html>").unwrap();
        let big: Vec<u8> = (0..300_000u32)
            .map(|i| u8::try_from(i % 97).unwrap().wrapping_add(b' '))
            .collect();
        std::fs::write(dir.join("big.txt"), big).unwrap();
        std::fs::write(dir.join("404.html"), b"<html>gone</html>").unwrap();
        dir.to_str().unwrap().to_owned().leak()
    }

    /// An origin the test plays, at `address`: one connection accepted,
    /// its request's head kept, and `body` sent back with a length, then
    /// closed.  `None` for an address nothing listens on.
    fn origin(body: Vec<u8>) -> (&'static str, thread::JoinHandle<Vec<u8>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let address: &'static str = l.local_addr().unwrap().to_string().leak();
        let handle = thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut head = Vec::new();
            let mut buf = [0u8; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = s.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                head.extend_from_slice(&buf[..n]);
            }
            s.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Origin: 1\r\n\
                     Set-Cookie: a=1\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .unwrap();
            s.write_all(&body).unwrap();
            head
        });
        (address, handle)
    }

    fn policy(root: &'static str) -> (Services<'static>, Listener<'static>) {
        policy_with(root, "127.0.0.1:1")
    }

    fn policy_with(root: &'static str, up: &'static str) -> (Services<'static>, Listener<'static>) {
        let services: &'static [(&str, Service<'_>)] = vec![
            (
                "www",
                Service::Files(Mount {
                    root,
                    default: "index.html",
                    cache: Cache::For {
                        max_age: 60,
                        revalidate: Revalidate::NotNeeded,
                        intermediaries: Intermediaries::Public,
                    },
                    mimes: &[],
                }),
            ),
            // the same tree's sub directory, as its own mount
            (
                "sub",
                Service::Files(Mount {
                    root: format!("{root}/sub").leak(),
                    default: "index.html",
                    cache: Cache::NoStore,
                    mimes: &[],
                }),
            ),
            (
                "up",
                Service::Proxy(Upstream {
                    address: up,
                    path: "/o",
                    host: "origin",
                }),
            ),
        ]
        .leak();
        let routes: &'static [Route<'static>] = vec![
            Route {
                path: "/",
                matching: Match::Prefix,
                to: "www",
                ws: Ws::NotTaken,
                headers: &[],
            },
            Route {
                path: "/sub",
                matching: Match::Prefix,
                to: "sub",
                ws: Ws::NotTaken,
                headers: &[(b"x-sub", b"1")],
            },
            Route {
                path: "/up",
                matching: Match::Prefix,
                to: "up",
                ws: Ws::NotTaken,
                headers: &[(b"x-up", b"1")],
            },
        ]
        .leak();
        let vhosts: &'static [Vhost<'static>] = vec![Vhost {
            name: "localhost",
            routes,
            headers: &[(b"x-front", b"1")],
            not_found: Some("/404.html"),
        }]
        .leak();
        (
            Services { by_name: services },
            Listener {
                name: "www",
                bind: "127.0.0.1:0",
                tls: Tls::Plain,
                h1: Config::default(),
                vhosts,
            },
        )
    }

    /// Everything the server answers `request` with, over one connection.
    fn ask(addr: std::net::SocketAddr, request: &str) -> Vec<u8> {
        let mut c = TcpStream::connect(addr).unwrap();
        c.write_all(request.as_bytes()).unwrap();
        let mut got = Vec::new();
        c.read_to_end(&mut got).unwrap();
        got
    }

    fn get(path: &str, extra: &str) -> String {
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{extra}Connection: close\r\n\r\n")
    }

    #[test]
    #[cfg_attr(miri, ignore = "sockets: native runs keep it")]
    fn files_are_served_through_the_runner_with_reads_off_the_turn() {
        let root = www("files_are_served_through_the_runner_with_reads_off_the_turn");
        let (services, listener) = policy(root);
        let listeners = [listener];
        check(&services, &listeners).unwrap();
        let log = format!("{root}/access.log");
        let logs = Logs::open(&[("localhost", &log)]).unwrap();
        let mut app = App {
            services,
            logs,
            dist: None,
        };
        let bound = bind(&listeners).unwrap();
        let addr = bound.local_addr(ListenerId::new(0)).unwrap();
        let stop = Stop::new();
        thread::scope(|scope| {
            let server = scope.spawn(|| {
                bound.serve(
                    4,
                    |ss: &mut Streams<'_, Front>, now, jobs| {
                        act(&mut app, ss, now, jobs);
                    },
                    Workers::default(),
                    &stop,
                )
            });
            // a failed assertion must still stop the server, or the scope
            // waits for it for ever
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                client(addr, root);
            }));
            stop.stop();
            server.join().unwrap().unwrap();
            if let Err(e) = outcome {
                std::panic::resume_unwind(e);
            }
        });
        // each request is a line of the vhost's access log, in C's
        // form, written as its transaction ended
        let lines = std::fs::read_to_string(&log).unwrap();
        drop(std::fs::remove_dir_all(root));
        let lines: Vec<&str> = lines.lines().collect();
        assert_eq!(lines.len(), 8, "{lines:?}");
        for l in &lines {
            assert!(l.starts_with("127.0.0.1 - - ["), "{l}");
            assert!(l.ends_with(" \"\" \"\""), "{l}");
        }
        assert!(
            lines[0].contains("] \"GET / HTTP/1.1\" 200 "),
            "{}",
            lines[0]
        );
        assert!(
            lines[2].contains("\"GET /sub HTTP/1.1\" 301 "),
            "{}",
            lines[2]
        );
        assert!(lines[3].contains("\"GET / HTTP/1.1\" 304 "), "{}", lines[3]);
        // the bytes are the whole answer: the head and the file
        let big = lines[4]
            .split_once("\"GET /big.txt HTTP/1.1\" 200 ")
            .and_then(|(_, rest)| rest.split_once(' '))
            .and_then(|(bytes, _)| bytes.parse::<u64>().ok())
            .unwrap_or(0);
        assert!((300_000..300_000 + 1024).contains(&big), "{}", lines[4]);
        assert!(
            lines[5].contains("\"HEAD /big.txt HTTP/1.1\" 200 "),
            "{}",
            lines[5]
        );
        assert!(
            lines[6].contains("\"GET /nothing HTTP/1.1\" 302 "),
            "{}",
            lines[6]
        );
    }

    /// What a client sees of the served tree.
    fn client(addr: std::net::SocketAddr, root: &str) {
        {
            let got1 = ask(addr, &get("/", ""));
            let text = String::from_utf8_lossy(&got1);
            assert!(text.starts_with("HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: 18\r\nx-front: 1\r\ncache-control: public, max-age=60\r\netag: 00000012"), "{text}");
            assert!(text.ends_with("\r\n\r\n<html>front</html>"));
            let etag_at = text.find("etag: ").unwrap().checked_add(6).unwrap();
            let etag = text[etag_at..etag_at.checked_add(16).unwrap()].to_owned();

            // the route's own headers, its mount, and the directory's
            // default document
            let got2 = ask(addr, &get("/sub/", ""));
            assert!(
                got2.ends_with(b"<html>sub</html>"),
                "{}",
                got2.escape_ascii()
            );
            assert!(String::from_utf8_lossy(&got2).contains("x-sub: 1\r\n"));
            // the route asked for without its /: C's redirect to add it
            let got3 = ask(addr, &get("/sub", ""));
            assert!(
                got3.starts_with(b"HTTP/1.1 301 Redirect\r\nlocation: http://localhost/sub/\r\n"),
                "{}",
                got3.escape_ascii()
            );

            // a 304 for the tag the server gave
            let got4 = ask(addr, &get("/", &format!("If-None-Match: {etag}\r\n")));
            assert!(
                got4.starts_with(b"HTTP/1.1 304 Not Modified\r\n"),
                "{}",
                got4.escape_ascii()
            );
            assert!(got4.ends_with(b"\r\n\r\n"));

            // the big file, read in chunks on the workers, goes whole
            let got5 = ask(addr, &get("/big.txt", ""));
            let at = got5
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .unwrap()
                .checked_add(4)
                .unwrap();
            assert_eq!(
                got5.len().checked_sub(at),
                Some(300_000),
                "{}",
                String::from_utf8_lossy(&got5[..at])
            );
            assert_eq!(
                got5[at..].to_vec(),
                std::fs::read(format!("{root}/big.txt")).unwrap()
            );

            // HEAD: the head alone
            let got6 = ask(
                addr,
                "HEAD /big.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            );
            assert!(got6.starts_with(
                b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 300000\r\n"
            ));
            assert!(got6.ends_with(b"\r\n\r\n"));

            // what is not there goes to the 404 document, which is
            let got7 = ask(addr, &get("/nothing", ""));
            assert!(
                got7.starts_with(b"HTTP/1.1 302 Redirect\r\nlocation: /404.html\r\n"),
                "{}",
                got7.escape_ascii()
            );
            let got8 = ask(addr, &get("/404.html", ""));
            assert!(got8.ends_with(b"<html>gone</html>"));
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "sockets: native runs keep it")]
    fn a_request_is_passed_to_the_origin_and_its_answer_back() {
        let body: Vec<u8> = (0..300_000u32)
            .map(|i| u8::try_from(i % 89).unwrap().wrapping_add(b'!'))
            .collect();
        let (up, origin) = origin(body.clone());
        let root = www("a_request_is_passed_to_the_origin_and_its_answer_back");
        let (services, listener) = policy_with(root, up);
        let listeners = [listener];
        let mut app = App {
            services,
            logs: Logs::none(),
            dist: None,
        };
        let bound = bind(&listeners).unwrap();
        let addr = bound.local_addr(ListenerId::new(0)).unwrap();
        let stop = Stop::new();
        thread::scope(|scope| {
            let server = scope.spawn(|| {
                bound.serve(
                    8,
                    |ss: &mut Streams<'_, Front>, now, jobs| {
                        act(&mut app, ss, now, jobs);
                    },
                    Workers::default(),
                    &stop,
                )
            });
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let got = ask(addr, &get("/up/x/y?q=1&r=a%20b", "Cookie: s=2\r\n"));
                let at = got
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .unwrap()
                    .checked_add(4)
                    .unwrap();
                let head = String::from_utf8_lossy(&got[..at]);
                assert!(
                    head.starts_with(
                        "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 300000\r\n\
                         x-front: 1\r\nx-up: 1\r\nset-cookie: a=1\r\n"
                    ),
                    "{head}"
                );
                assert!(!head.contains("x-origin"));
                assert_eq!(got.len().checked_sub(at), Some(body.len()));
                assert_eq!(got[at..], body[..]);
                let sent = origin.join().unwrap();
                let sent = String::from_utf8_lossy(&sent);
                assert!(
                    sent.starts_with("GET /o/x/y?q=1&r=a%20b HTTP/1.1\r\nHost: localhost\r\n"),
                    "{sent}"
                );
                assert!(sent.contains("cookie: s=2\r\n"), "{sent}");
            }));
            stop.stop();
            server.join().unwrap().unwrap();
            if let Err(e) = outcome {
                std::panic::resume_unwind(e);
            }
        });
        drop(std::fs::remove_dir_all(root));
    }

    #[test]
    #[cfg_attr(miri, ignore = "sockets: native runs keep it")]
    fn an_origin_not_there_is_answered_503() {
        // bound then dropped: nothing listens there
        let nowhere: &'static str = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .to_string()
            .leak();
        let root = www("an_origin_not_there_is_answered_503");
        let (services, listener) = policy_with(root, nowhere);
        let listeners = [listener];
        let mut app = App {
            services,
            logs: Logs::none(),
            dist: None,
        };
        let bound = bind(&listeners).unwrap();
        let addr = bound.local_addr(ListenerId::new(0)).unwrap();
        let stop = Stop::new();
        thread::scope(|scope| {
            let server = scope.spawn(|| {
                bound.serve(
                    4,
                    |ss: &mut Streams<'_, Front>, now, jobs| {
                        act(&mut app, ss, now, jobs);
                    },
                    Workers::default(),
                    &stop,
                )
            });
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let got = ask(addr, &get("/up/", ""));
                assert!(
                    got.starts_with(b"HTTP/1.1 503 Service Unavailable\r\n"),
                    "{}",
                    got.escape_ascii()
                );
            }));
            stop.stop();
            server.join().unwrap().unwrap();
            if let Err(e) = outcome {
                std::panic::resume_unwind(e);
            }
        });
        drop(std::fs::remove_dir_all(root));
    }

    #[test]
    fn a_route_naming_no_built_in_service_is_refused_with_the_list() {
        let (services, listener) = policy("/nowhere");
        let routes = [Route {
            to: "login",
            ..listener.vhosts[0].routes[0]
        }];
        let vhosts = [Vhost {
            routes: &routes,
            ..listener.vhosts[0]
        }];
        let bad = [Listener {
            vhosts: &vhosts,
            ..listener
        }];
        let e = check(&services, &bad).unwrap_err();
        assert_eq!(
            e.to_string(),
            "www, localhost, /: no service \"login\"; built in: www, sub, up"
        );
    }

    /// A script in `root` that answers with its head, what it was told,
    /// and its stdin: the path to it.
    #[cfg(unix)]
    fn script(root: &str) -> &'static str {
        use std::os::unix::fs::PermissionsExt;
        let path = format!("{root}/answer.sh");
        std::fs::write(
            &path,
            "#!/bin/sh\n\
             if [ \"$PATH_INFO\" = /fail ]; then exit 3; fi\n\
             if [ \"$PATH_INFO\" = /there ]; then printf 'Location: /elsewhere\\r\\n\\r\\n'; exit 0; fi\n\
             printf 'Status: 201 Created\\r\\nContent-Type: text/plain\\r\\nX-Info: %s\\r\\n\\r\\n' \"$PATH_INFO\"\n\
             printf 'method=%s query=%s uri=%s https=%s\\n' \"$REQUEST_METHOD\" \"$QUERY_STRING\" \"$REQUEST_URI\" \"$HTTPS\"\n\
             cat\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.leak()
    }

    /// The services and a plain listener: the tree, and a cgi route to
    /// `exec`.
    fn policy_cgi(
        root: &'static str,
        exec: &'static str,
    ) -> (Services<'static>, Listener<'static>) {
        let services: &'static [(&'static str, Service<'static>)] = vec![
            (
                "www",
                Service::Files(Mount {
                    root,
                    default: "index.html",
                    cache: Cache::NoStore,
                    mimes: &[],
                }),
            ),
            (
                "cgi",
                Service::Cgi(Script {
                    exec,
                    env: &[("SCRIPT_OWN", "yes")],
                    dir: Some(root),
                    timeout: Duration::from_secs(5),
                }),
            ),
        ]
        .leak();
        let routes: &'static [Route<'static>] = vec![
            Route {
                path: "/",
                matching: Match::Prefix,
                to: "www",
                ws: Ws::NotTaken,
                headers: &[],
            },
            Route {
                path: "/cgi",
                matching: Match::Prefix,
                to: "cgi",
                ws: Ws::NotTaken,
                headers: &[(b"x-cgi", b"1")],
            },
        ]
        .leak();
        let vhosts: &'static [Vhost<'static>] = vec![Vhost {
            name: "localhost",
            routes,
            headers: &[],
            not_found: None,
        }]
        .leak();
        (
            Services { by_name: services },
            Listener {
                name: "www",
                bind: "127.0.0.1:0",
                tls: Tls::Plain,
                h1: Config::default(),
                vhosts,
            },
        )
    }

    #[test]
    #[cfg(unix)]
    #[cfg_attr(miri, ignore = "sockets and processes: native runs keep it")]
    fn a_script_answers_from_its_environment_and_its_stdin() {
        let root = www("a_script_answers_from_its_environment_and_its_stdin");
        let exec = script(root);
        let (services, listener) = policy_cgi(root, exec);
        let listeners = [listener];
        let mut app = App {
            services,
            logs: Logs::none(),
            dist: None,
        };
        let bound = bind(&listeners).unwrap();
        let addr = bound.local_addr(ListenerId::new(0)).unwrap();
        let stop = Stop::new();
        thread::scope(|scope| {
            let server = scope.spawn(|| {
                bound.serve(
                    4,
                    |ss: &mut Streams<'_, Front>, now, jobs| {
                        act(&mut app, ss, now, jobs);
                    },
                    Workers::default(),
                    &stop,
                )
            });
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                // the head's status and headers, the route's header, and
                // the environment, with no length so the close ends it
                let got1 = ask(addr, &get("/cgi/a/b?x=1&y=a%26b", ""));
                let text1 = String::from_utf8_lossy(&got1);
                assert!(
                    text1.starts_with(
                        "HTTP/1.1 201 \r\ncontent-type: text/plain\r\nconnection: close\r\n\
                         x-cgi: 1\r\nX-Info: /a/b\r\n\r\n"
                    ),
                    "{text1}"
                );
                assert!(
                    text1.ends_with("method=GET query=x=1&y=a%26b uri=/cgi/a/b https=\n"),
                    "{text1}"
                );
                // a POST's body goes to its stdin, and comes back from cat
                let body = "hello, script";
                let got2 = ask(
                    addr,
                    &format!(
                        "POST /cgi/in HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\
                         Connection: close\r\n\r\n{body}",
                        body.len()
                    ),
                );
                let text2 = String::from_utf8_lossy(&got2);
                assert!(text2.starts_with("HTTP/1.1 201 \r\n"), "{text2}");
                assert!(
                    text2.ends_with(&format!("method=POST query= uri=/cgi/in https=\n{body}")),
                    "{text2}"
                );
                // a Location is a 302
                let got3 = ask(addr, &get("/cgi/there", ""));
                assert!(
                    got3.starts_with(
                        b"HTTP/1.1 302 Redirect\r\nconnection: close\r\nx-cgi: 1\r\nLocation: /elsewhere\r\n"
                    ),
                    "{}",
                    got3.escape_ascii()
                );
                // one that exits without a head: C's page
                let got4 = ask(addr, &get("/cgi/fail", ""));
                assert!(
                    got4.starts_with(b"HTTP/1.1 500 Internal Server Error\r\n"),
                    "{}",
                    got4.escape_ascii()
                );
                // a HEAD gets the head alone
                let got5 = ask(
                    addr,
                    "HEAD /cgi/h HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                );
                let text5 = String::from_utf8_lossy(&got5);
                assert!(text5.starts_with("HTTP/1.1 201 \r\n"), "{text5}");
                assert!(text5.ends_with("\r\n\r\n"), "{text5}");
            }));
            stop.stop();
            server.join().unwrap().unwrap();
            if let Err(e) = outcome {
                std::panic::resume_unwind(e);
            }
        });
        drop(std::fs::remove_dir_all(root));
    }
}
