//! The front over real sockets: a directory served by npro-files through
//! the runner, its reads done by the adapter's workers, a 404 document,
//! a 304, a HEAD, and a policy naming a service that is not built in.

#![expect(
    unused_crate_dependencies,
    reason = "an integration test sees all of its crate's dependencies; this one uses npro-cli, npro-core, npro-files, npro-io and npro-ss"
)]

// held to clippy's rules for tests
#[cfg(test)]
mod front {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::path::PathBuf;
    use std::thread;

    use npro_cli::front::{Front, Service, Services, act, check};
    use npro_cli::runner::{Streams, bind};
    use npro_files::{Cache, Intermediaries, Mount, Revalidate};
    use npro_h1::server::Config;
    use npro_io::threads::{Stop, Workers};
    use npro_ss::id::ListenerId;
    use npro_ss::policy::{Listener, Match, Route, Tls, Vhost, Ws};

    /// A directory of files to serve: its path, leaked for the policy.
    fn www() -> &'static str {
        let dir: PathBuf = std::env::temp_dir().join(format!("npro-front-{}", std::process::id()));
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

    fn policy(root: &'static str) -> (Services<'static>, Listener<'static>) {
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
        let root = www();
        let (services, listener) = policy(root);
        let listeners = [listener];
        check(&services, &listeners).unwrap();
        let bound = bind(&listeners).unwrap();
        let addr = bound.local_addr(ListenerId::new(0)).unwrap();
        let stop = Stop::new();
        thread::scope(|scope| {
            let server = scope.spawn(|| {
                bound.serve(
                    4,
                    |ss: &mut Streams<'_, Front>, now, jobs| act(&services, ss, now, jobs),
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
        drop(std::fs::remove_dir_all(root));
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
            "www, localhost, /: no service \"login\"; built in: www, sub"
        );
    }
}
