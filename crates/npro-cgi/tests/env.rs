//! The script's environment, from a request on npro-ss' streams in
//! memory: variable for variable as C composes it.

// held to clippy's rules for tests
#[cfg(test)]
mod env {
    use core::time::Duration;

    use npro_cgi::{EnvError, MAX_ENV, Script, Vars};
    use npro_core::random::SeededRandom;
    use npro_core::time::Instant;
    use npro_h1::server::Config;
    use npro_io::driver::{Buffers, NetBuffers, Want};
    use npro_ss::event::Kind;
    use npro_ss::id::ListenerId;
    use npro_ss::policy::{Listener, Match, Route, Tls, Vhost, Ws};
    use npro_ss::ss::{ConnStorage, Slot, Ss};

    const T0: Instant = Instant::from_micros(1_000_000);

    const ROUTES: [Route<'static>; 1] = [Route {
        path: "/repo",
        matching: Match::Prefix,
        to: "git",
        ws: Ws::NotTaken,
        headers: &[],
    }];

    const VHOSTS: [Vhost<'static>; 1] = [Vhost {
        name: "npro.rs",
        routes: &ROUTES,
        headers: &[],
        not_found: None,
    }];

    const GIT: Script<'static> = Script {
        exec: "/usr/libexec/git-core/git-http-backend",
        env: &[
            ("GIT_PROJECT_ROOT", "/srv/git"),
            ("GIT_HTTP_EXPORT_ALL", ""),
        ],
        dir: None,
        timeout: Duration::from_secs(30),
    };

    fn slot() -> Slot<(), Vec<u8>, SeededRandom> {
        Slot::new(ConnStorage {
            h1: npro_h1::Storage {
                table: vec![0; 16384],
                out: vec![0; 1024],
            },
            bufs: Buffers {
                rx: vec![0; 16384],
                tx: vec![0; 1024],
                inflate: Vec::new(),
            },
            net: NetBuffers {
                rx: Vec::new(),
                tx: Vec::new(),
            },
        })
    }

    /// The environment for `request` on a listener with `tls`, as a
    /// list of `NAME=value`.
    fn vars_for(tls: Tls<'static>, request: &[u8]) -> Result<Vec<String>, EnvError> {
        with_request(tls, request, |txn| {
            Vars::of(&GIT, txn).map(|v| {
                v.iter()
                    .map(|(n, v)| {
                        format!(
                            "{}={}",
                            String::from_utf8_lossy(n),
                            String::from_utf8_lossy(v)
                        )
                    })
                    .collect()
            })
        })
    }

    /// `f` given the request `request` comes to, on a listener with
    /// `tls`.
    fn with_request<R>(
        tls: Tls<'static>,
        request: &[u8],
        f: impl FnOnce(&npro_ss::event::Txn<'_, Vec<u8>>) -> R,
    ) -> R {
        let listeners = [Listener {
            name: "www",
            bind: "unix:/www",
            tls,
            h1: Config::default(),
            vhosts: &VHOSTS,
        }];
        let mut slots = vec![slot()];
        let mut ss = Ss::new(&listeners, &mut slots).unwrap();
        let conn = ss.accepted(T0, ListenerId::new(0), None, None).unwrap();
        let Ok(Want::Io(io)) = ss.want(T0, conn) else {
            panic!("not io");
        };
        io.read.unwrap()[..request.len()].copy_from_slice(request);
        ss.read_done(T0, conn, request.len()).unwrap();
        let mut f = Some(f);
        let mut out = None;
        while let Some(ev) = ss.poll_event(T0) {
            if let Kind::ServerTxn(txn) = ev.kind {
                if let Some(f) = f.take() {
                    out = Some(f(&txn));
                }
            }
        }
        out.expect("no request")
    }

    #[test]
    fn gits_environment_is_cs_variable_for_variable() {
        // (a tls listener needs a record layer to accept on, which the
        // runner's sockets tests have: `HTTPS=ON` is checked there)
        let vars = vars_for(
            Tls::Plain,
            b"GET /repo/npro.git/info/refs?service=git-upload-pack&x=a%26b HTTP/1.1\r\n\
              Host: npro.rs\r\nUser-Agent: git/2.45\r\nAccept: */*\r\nAccept-Encoding: deflate, gzip\r\n\
              Pragma: no-cache\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            vars,
            [
                "REQUEST_METHOD=GET",
                // the decoded `&` encoded again, so it cannot split
                "QUERY_STRING=service=git-upload-pack&x=a%26b",
                "REQUEST_URI=/repo/npro.git/info/refs",
                "PATH_INFO=/npro.git/info/refs",
                "HTTP_HOST=npro.rs",
                "HTTP_USER_AGENT=git/2.45",
                "HTTP_ACCEPT=*/*",
                "HTTP_ACCEPT_ENCODING=deflate, gzip",
                "PATH=/bin:/usr/bin:/usr/local/bin:/var/www/cgi-bin",
                "SCRIPT_PATH=/usr/libexec/git-core/git-http-backend",
                "GIT_PROJECT_ROOT=/srv/git",
                "GIT_HTTP_EXPORT_ALL=",
                "SERVER_SOFTWARE=npro",
            ]
        );
        assert!(Vars::is_git(&GIT));
    }

    #[test]
    fn a_post_tells_the_script_its_body_and_a_plain_listener_no_https() {
        let vars = vars_for(
            Tls::Plain,
            b"POST /repo/npro.git/git-upload-pack HTTP/1.1\r\nHost: npro.rs\r\n\
              Content-Type: application/x-git-upload-pack-request\r\nContent-Length: 7\r\n\
              Content-Encoding: gzip\r\nCookie: a=1\r\nReferer: https://npro.rs/\r\n\r\nabcdefg",
        )
        .unwrap();
        assert_eq!(
            vars.first().map(String::as_str),
            Some("REQUEST_METHOD=POST")
        );
        assert!(vars.contains(&"QUERY_STRING=".to_owned()));
        assert!(vars.contains(&"PATH_INFO=/npro.git/git-upload-pack".to_owned()));
        assert!(vars.contains(&"HTTP_REFERER=https://npro.rs/".to_owned()));
        assert!(vars.contains(&"HTTP_COOKIE=a=1".to_owned()));
        assert!(vars.contains(&"HTTP_CONTENT_ENCODING=gzip".to_owned()));
        assert!(vars.contains(&"CONTENT_TYPE=application/x-git-upload-pack-request".to_owned()));
        assert!(vars.contains(&"CONTENT_LENGTH=7".to_owned()));
        assert!(!vars.iter().any(|v| v.starts_with("HTTPS=")));
    }

    #[test]
    fn what_does_not_fit_is_refused() {
        let long = "x".repeat(MAX_ENV);
        let request = format!("GET /repo/a?{long} HTTP/1.1\r\nHost: npro.rs\r\n\r\n");
        assert_eq!(
            vars_for(Tls::Plain, request.as_bytes()),
            Err(EnvError::TooLong)
        );
    }
}
