//! The file service over npro-ss' streams, in memory: a tree of files,
//! requests read in, and what is written compared with what C writes.
//! The reads a runner would do off the turn are done here as they are
//! wanted.

// held to clippy's rules for tests
#[cfg(test)]
mod serve {
    use npro_core::random::SeededRandom;
    use npro_core::time::Instant;
    use npro_files::{
        CHUNK, Cache, Fs, Intermediaries, Mount, Opened, Revalidate, Scheme, Served, Serving, serve,
    };
    use npro_h1::server::Config;
    use npro_io::driver::{Buffers, Io, NetBuffers, Want};
    use npro_ss::event::{Filled, Kind};
    use npro_ss::id::ListenerId;
    use npro_ss::policy::{Listener, Match, Route, Tls, Vhost, Ws};
    use npro_ss::ss::{ConnStorage, Slot, Ss};

    const T0: Instant = Instant::from_micros(1_000_000);

    /// A file in the tree: its path and its bytes, changed at `MODIFIED`.
    type File = (&'static str, Vec<u8>);

    const MODIFIED: u32 = 0x6553_F100;

    /// A tree in memory: files by path, and the directories above them.
    struct Tree(Vec<File>);

    impl Fs for Tree {
        /// Which file: the runner reads it by index.
        type File = usize;

        fn open(&mut self, path: &[u8]) -> Option<Opened<usize>> {
            if let Some(i) = self.0.iter().position(|(p, _)| p.as_bytes() == path) {
                return Some(Opened::File {
                    file: i,
                    len: u64::try_from(self.0[i].1.len()).unwrap(),
                    modified: MODIFIED,
                });
            }
            // a directory, asked for with or without its /
            let dir = [path.strip_suffix(b"/").unwrap_or(path), b"/"].concat();
            self.0
                .iter()
                .any(|(p, _)| p.as_bytes().starts_with(&dir))
                .then_some(Opened::Dir)
        }
    }

    const WWW: Mount<'static> = Mount {
        root: "/srv/www",
        default: "index.html",
        cache: Cache::For {
            max_age: 172_800,
            revalidate: Revalidate::NotNeeded,
            intermediaries: Intermediaries::Private,
        },
        mimes: &[(".tar.gz", "application/x-gtar")],
    };

    const DOCS: Mount<'static> = Mount {
        root: "/srv/docs/",
        default: "index.html",
        cache: Cache::NoStore,
        mimes: &[],
    };

    const ROUTES: [Route<'static>; 3] = [
        Route {
            path: "/",
            matching: Match::Prefix,
            to: "www",
            ws: Ws::NotTaken,
            headers: &[],
        },
        Route {
            path: "/docs",
            matching: Match::Prefix,
            to: "docs",
            ws: Ws::NotTaken,
            headers: &[(b"x-docs", b"1")],
        },
        Route {
            path: "/cb",
            matching: Match::Prefix,
            to: "app",
            ws: Ws::NotTaken,
            headers: &[],
        },
    ];

    fn vhost(not_found: Option<&'static str>) -> Vhost<'static> {
        Vhost {
            name: "test",
            routes: &ROUTES,
            headers: &[(b"x-vhost", b"1")],
            not_found,
        }
    }

    /// A stream's state: what it is sending.
    #[derive(Default)]
    enum App {
        #[default]
        Idle,
        Answered,
        Body(Serving<usize, Vec<u8>>),
    }

    type S<'s> = Ss<'s, App, Vec<u8>, SeededRandom>;

    fn slots() -> Vec<Slot<App, Vec<u8>, SeededRandom>> {
        vec![Slot::new(ConnStorage {
            h1: npro_h1::Storage {
                table: vec![0; 2048],
                out: vec![0; 2048],
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

    /// Serves `request` from `tree` on a vhost with `not_found`: what is
    /// written, and how many reads were done.
    fn answer(
        tree: &mut Tree,
        not_found: Option<&'static str>,
        request: &[u8],
    ) -> (Vec<u8>, usize) {
        let vhosts = [vhost(not_found)];
        let listeners = [Listener {
            name: "test",
            bind: "unix:/test",
            tls: Tls::Plain,
            h1: Config::default(),
            vhosts: &vhosts,
        }];
        let mut sl = slots();
        let mut ss: S<'_> = Ss::new(&listeners, &mut sl).unwrap();
        let conn = ss.accepted(T0, ListenerId::new(0), None, None).unwrap();
        let Ok(Want::Io(io)) = ss.want(T0, conn) else {
            panic!("not io");
        };
        io.read.unwrap()[..request.len()].copy_from_slice(request);
        ss.read_done(T0, conn, request.len()).unwrap();
        let mut out = Vec::new();
        let mut reads = 0usize;
        for _ in 0..1000 {
            let mut moved = false;
            while let Some(ev) = ss.poll_event(T0) {
                moved = true;
                let (stream, user) = (ev.stream, ev.user);
                match ev.kind {
                    Kind::ServerTxn(mut txn) => {
                        let served = match txn.route().map(|r| r.route.to) {
                            Some("www") => serve(&WWW, &mut txn, tree, Scheme::Https),
                            Some("docs") => serve(&DOCS, &mut txn, tree, Scheme::Http),
                            // the application's own: nothing there
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
                        // the runner's read, done here and now
                        if let App::Body(s) = user {
                            if let Some((file, read)) = s.wanted() {
                                reads = reads.checked_add(1).unwrap();
                                let bytes = &tree.0[file].1;
                                let at = usize::try_from(read.at).unwrap();
                                let end = at.checked_add(read.len).unwrap().min(bytes.len());
                                s.read_done(file, bytes[at.min(end)..end].to_vec());
                                ss.request_tx(stream).unwrap();
                            }
                        }
                    }
                    Kind::ServerUpgrade { .. }
                    | Kind::UpgradeRefused(_)
                    | Kind::Rx { .. }
                    | Kind::Pong
                    | Kind::PeerClose { .. }
                    | Kind::ServerTxnEnd(_)
                    | Kind::Response(_)
                    | Kind::ConnectFailed
                    | Kind::Disconnected => {}
                }
            }
            while let Ok(Want::Io(Io { write: Some(w), .. })) = ss.want(T0, conn) {
                moved = true;
                let n = w.len();
                out.extend_from_slice(w);
                ss.write_done(T0, conn, n).unwrap();
            }
            if !moved {
                break;
            }
        }
        (out, reads)
    }

    fn tree() -> Tree {
        Tree(vec![
            ("/srv/www/index.html", b"<html>hi</html>".to_vec()),
            ("/srv/www/a/index.html", b"<html>a</html>".to_vec()),
            (
                "/srv/www/big.txt",
                (0..100_000u32)
                    .map(|i| b'a'.checked_add(u8::try_from(i % 26).unwrap()).unwrap())
                    .collect(),
            ),
            ("/srv/www/empty.txt", Vec::new()),
            ("/srv/www/x.tar.gz", vec![0x1f, 0x8b]),
            ("/srv/www/README.md", b"# no type".to_vec()),
            ("/srv/docs/index.html", b"docs".to_vec()),
        ])
    }

    const CRLF: &str = "\r\n\r\n";

    fn get(path: &str) -> Vec<u8> {
        format!("GET {path} HTTP/1.1\r\nHost: test\r\n\r\n").into_bytes()
    }

    #[test]
    fn a_file_is_served_with_its_type_cache_control_and_etag() {
        let (out1, reads) = answer(&mut tree(), None, &get("/index.html"));
        assert_eq!(
            String::from_utf8_lossy(&out1),
            "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: 15\r\n\
             x-vhost: 1\r\ncache-control: private, max-age=172800\r\netag: 0000000F6553F100\
             \r\n\r\n<html>hi</html>"
        );
        assert_eq!(reads, 1);
        // the mount's own type before C's .gz, and C's for the rest
        let (out2, _) = answer(&mut tree(), None, &get("/x.tar.gz"));
        assert!(out2.starts_with(b"HTTP/1.1 200 OK\r\ncontent-type: application/x-gtar\r\n"));
        // a type nothing knows is refused
        let (out3, _) = answer(&mut tree(), None, &get("/README.md"));
        assert!(out3.starts_with(b"HTTP/1.1 415 Unsupported Media Type\r\n"));
    }

    #[test]
    fn a_directory_gets_its_default_document_or_its_slash() {
        let (out1, _) = answer(&mut tree(), None, &get("/"));
        assert!(out1.ends_with(b"<html>hi</html>"));
        let (out2, _) = answer(&mut tree(), None, &get("/a/"));
        assert!(out2.ends_with(b"<html>a</html>"), "{}", out2.escape_ascii());
        // under the route, a directory is a path like any: the default
        // document, no redirect
        let (out3, _) = answer(&mut tree(), None, &get("/a"));
        assert!(out3.ends_with(b"<html>a</html>"));
        // the route itself asked for without its /: C's 301 to add it
        let (out4, _) = answer(&mut tree(), None, &get("/docs"));
        assert_eq!(
            String::from_utf8_lossy(&out4),
            "HTTP/1.1 301 Redirect\r\nlocation: http://test/docs/\r\ncontent-type: text/html\
             \r\ncontent-length: 0\r\nx-vhost: 1\r\nx-docs: 1\r\n\r\n"
        );
        let (out5, _) = answer(&mut tree(), None, &get("/docs/"));
        assert!(out5.ends_with(
            b"x-docs: 1\r\ncache-control: no-store\r\netag: 000000046553F100\r\n\r\ndocs"
        ));
    }

    #[test]
    fn a_matching_etag_is_304_and_a_head_is_the_head_alone() {
        let req =
            b"GET /index.html HTTP/1.1\r\nHost: test\r\nIf-None-Match: 0000000F6553F100\r\n\r\n";
        let (out1, reads1) = answer(&mut tree(), None, req);
        assert_eq!(
            String::from_utf8_lossy(&out1),
            "HTTP/1.1 304 Not Modified\r\nx-vhost: 1\r\netag: 0000000F6553F100\r\n\
             cache-control: private, max-age=172800\r\n\r\n"
        );
        assert_eq!(reads1, 0);
        let (out2, reads2) = answer(
            &mut tree(),
            None,
            b"HEAD /big.txt HTTP/1.1\r\nHost: test\r\n\r\n",
        );
        assert!(out2.starts_with(
            b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 100000\r\n"
        ));
        assert!(out2.ends_with(CRLF.as_bytes()));
        assert_eq!(reads2, 0);
        let (out3, reads3) = answer(&mut tree(), None, &get("/empty.txt"));
        assert!(out3.ends_with(b"content-length: 0\r\nx-vhost: 1\r\ncache-control: private, max-age=172800\r\netag: 000000006553F100\r\n\r\n"));
        assert_eq!(reads3, 0);
    }

    #[test]
    fn a_large_file_goes_whole_a_chunk_at_a_time() {
        let t = tree();
        let want = t.0[2].1.clone();
        let (out1, reads) = answer(&mut tree(), None, &get("/big.txt"));
        let at = out1.windows(4).position(|w| w == CRLF.as_bytes()).unwrap() + 4;
        assert_eq!(&out1[at..], &want[..]);
        assert_eq!(reads, want.len().div_ceil(CHUNK));
    }

    #[test]
    fn what_is_not_there_is_404_or_the_vhosts_document_and_outside_is_403() {
        let (out1, _) = answer(&mut tree(), None, &get("/nothing"));
        assert!(out1.starts_with(b"HTTP/1.1 404 Not Found\r\n"));
        let (out2, _) = answer(&mut tree(), Some("/404.html"), &get("/nothing"));
        assert!(out2.starts_with(b"HTTP/1.1 302 Redirect\r\nlocation: /404.html\r\n"));
        // the document itself, not there, is the page
        let (out3, _) = answer(&mut tree(), Some("/404.html"), &get("/404.html"));
        assert!(out3.starts_with(b"HTTP/1.1 404 Not Found\r\n"));
        // the parser takes .. out3; what it leaves is checked once more
        let (out4, _) = answer(&mut tree(), None, &get("/a/%5c../index.html"));
        assert!(
            out4.starts_with(b"HTTP/1.1 403 Forbidden\r\n"),
            "{}",
            out4.escape_ascii()
        );
        // another route's answer is the application's
        let (out5, _) = answer(&mut tree(), Some("/404.html"), &get("/cb/y"));
        assert!(out5.starts_with(b"HTTP/1.1 302 Redirect\r\nlocation: /404.html\r\n"));
    }
}
