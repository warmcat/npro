//! The runner over real sockets: listeners bound from a policy, the
//! capabilities dropped, h1 answered plain and over tls with aws-lc, and
//! what it refuses.  The certificates are npro-aws-lc's test ones, written
//! out as PEM, as a policy names them by path.

#![expect(
    unused_crate_dependencies,
    reason = "an integration test sees all of its crate's dependencies; this one uses npro-cli, npro-core, npro-ss, rustls and, on Linux, caps"
)]

// held to clippy's rules for tests
#[cfg(test)]
mod runner {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::thread;

    use npro_cli::runner::{RunError, Streams, bind};
    use npro_cli::tls::{CHECK_EVERY, CertError, Certs};
    use npro_core::time::Instant;
    use npro_h1::server::Config;
    use npro_io::threads::{Jobs, Stop, Workers};
    use npro_ss::event::{Filled, Kind, Response};
    use npro_ss::id::ListenerId;
    use npro_ss::policy::{Listener, Match, Route, Tls, Vhost, Ws};
    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

    const CERTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../npro-aws-lc/tests/certs");

    fn der(name: &str) -> Vec<u8> {
        std::fs::read(format!("{CERTS}/{name}")).unwrap()
    }

    fn pem(label: &str, der: &[u8]) -> String {
        let mut b64 = vec![0u8; npro_core::base64::encoded_len(der.len()).unwrap()];
        let n = npro_core::base64::encode(der, &mut b64).unwrap();
        let mut out = format!("-----BEGIN {label}-----\n");
        for line in b64[..n].chunks(64) {
            out.push_str(core::str::from_utf8(line).unwrap());
            out.push('\n');
        }
        out.push_str("-----END ");
        out.push_str(label);
        out.push_str("-----\n");
        out
    }

    /// The test chain and key as PEM files, in a directory of `name`'s:
    /// their paths, as a policy names them.
    fn pem_files(name: &str) -> (&'static str, &'static str) {
        let dir: PathBuf =
            std::env::temp_dir().join(format!("npro-cli-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        let chain = pem("CERTIFICATE", &der("leaf.der")) + &pem("CERTIFICATE", &der("ca.der"));
        std::fs::write(&cert, chain).unwrap();
        std::fs::write(&key, pem("PRIVATE KEY", &der("leaf-key.der"))).unwrap();
        let leak = |p: PathBuf| -> &'static str { p.to_str().unwrap().to_owned().leak() };
        (leak(cert), leak(key))
    }

    const VHOSTS: [Vhost<'static>; 1] = [Vhost {
        name: "localhost",
        routes: &[Route {
            path: "/",
            matching: Match::Prefix,
            to: "app",
            ws: Ws::NotTaken,
            headers: &[],
        }],
        headers: &[(b"x-runner", b"1")],
        not_found: None,
    }];

    fn listener(name: &'static str, tls: Tls<'static>) -> Listener<'static> {
        Listener {
            name,
            bind: "127.0.0.1:0",
            tls,
            h1: Config::default(),
            vhosts: &VHOSTS,
        }
    }

    /// A stream's state: its answer, and how much of it went.
    #[derive(Default)]
    struct App {
        out: Vec<u8>,
        at: usize,
    }

    /// Answers each request with its path.
    fn app(ss: &mut Streams<'_, App>, now: Instant, _: &Jobs<'_, Streams<'_, App>>) {
        while let Some(ev) = ss.poll_event(now) {
            let (stream, user) = (ev.stream, ev.user);
            let tx = match ev.kind {
                Kind::ServerTxn(mut txn) => {
                    user.out = txn.path().unwrap_or_default().to_vec();
                    user.at = 0;
                    txn.respond(Response {
                        status: 200,
                        content_type: Some(b"text/plain"),
                        content_length: Some(u64::try_from(user.out.len()).unwrap()),
                        headers: &[],
                    })
                    .unwrap();
                    true
                }
                Kind::Tx(t) => {
                    t.fill(|buf| {
                        let rest = &user.out[user.at..];
                        let n = rest.len().min(buf.len());
                        buf[..n].copy_from_slice(&rest[..n]);
                        user.at = user.at.checked_add(n).unwrap();
                        Filled::Last(n)
                    });
                    false
                }
                Kind::ServerUpgrade { .. }
                | Kind::UpgradeRefused(_)
                | Kind::ClientUpgraded { .. }
                | Kind::NotUpgraded { .. }
                | Kind::Rx { .. }
                | Kind::Pong
                | Kind::PeerClose { .. }
                | Kind::ServerTxnEnd(_)
                | Kind::Response(_)
                | Kind::ConnectFailed
                | Kind::Disconnected => false,
            };
            if tx {
                ss.request_tx(stream).unwrap();
            }
        }
    }

    const GET: &[u8] = b"GET /path HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";

    fn answered(got: &[u8]) {
        assert!(
            got.starts_with(b"HTTP/1.1 200 OK\r\n"),
            "{}",
            got.escape_ascii()
        );
        assert!(
            got.ends_with(b"x-runner: 1\r\n\r\n/path"),
            "{}",
            got.escape_ascii()
        );
    }

    fn tls_client() -> Arc<ClientConfig> {
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(der("ca.der"))).unwrap();
        let mut c = ClientConfig::builder_with_provider(npro_aws_lc::provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        c.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(c)
    }

    #[test]
    #[cfg_attr(miri, ignore = "sockets: native runs keep it")]
    fn h1_is_answered_plain_and_over_tls() {
        let (cert, key) = pem_files("both");
        let listeners = [
            listener("plain", Tls::Plain),
            listener("tls", Tls::Server { cert, key }),
        ];
        let bound = bind(&listeners).unwrap();
        let plain = bound.local_addr(ListenerId::new(0)).unwrap();
        let tls = bound.local_addr(ListenerId::new(1)).unwrap();
        let stop = Stop::new();
        thread::scope(|scope| {
            let server = scope.spawn(|| bound.serve(4, app, Workers::default(), &stop));

            let mut c = TcpStream::connect(plain).unwrap();
            c.write_all(GET).unwrap();
            let mut got = Vec::new();
            c.read_to_end(&mut got).unwrap();
            answered(&got);

            let conn =
                ClientConnection::new(tls_client(), ServerName::try_from("localhost").unwrap())
                    .unwrap();
            let mut s = StreamOwned::new(conn, TcpStream::connect(tls).unwrap());
            s.write_all(GET).unwrap();
            let mut over_tls = Vec::new();
            // the server's close_notify ends it
            s.read_to_end(&mut over_tls).unwrap();
            answered(&over_tls);
            assert_eq!(s.conn.alpn_protocol(), Some(&b"http/1.1"[..]));

            stop.stop();
            server.join().unwrap().unwrap();
        });
    }

    #[test]
    fn certificates_changed_on_disk_are_taken_once_they_load() {
        let (cert, key) = pem_files("reload");
        let t0 = std::time::Instant::now();
        let later = |n: u32| t0.checked_add(CHECK_EVERY.checked_mul(n).unwrap()).unwrap();
        let mut c = Certs::load(cert.as_ref(), key.as_ref(), t0).unwrap();
        let first = c.config(t0);
        let good = std::fs::read(cert).unwrap();
        // half written: kept as it was, and why said
        std::fs::write(cert, b"-----BEGIN CERTIFICATE-----\nnot base64\n").unwrap();
        // not looked at again until it is time
        assert!(Arc::ptr_eq(&c.config(t0), &first));
        assert!(c.failed().is_none());
        assert!(Arc::ptr_eq(&c.config(later(1)), &first));
        assert!(matches!(c.failed(), Some(CertError::Cert(_))));
        // whole again: a new config, for the connections after
        std::fs::write(cert, &good).unwrap();
        let renewed = c.config(later(2));
        assert!(!Arc::ptr_eq(&renewed, &first));
        assert!(c.failed().is_none());
        // unchanged since: the same one
        assert!(Arc::ptr_eq(&c.config(later(3)), &renewed));
    }

    #[test]
    #[cfg(target_os = "linux")]
    #[cfg_attr(miri, ignore = "capabilities: native runs keep it")]
    fn once_bound_no_capability_is_left() {
        let listeners = [listener("plain", Tls::Plain)];
        // on this thread, as the runner's caller does it
        let bound = bind(&listeners).unwrap();
        for set in [
            caps::CapSet::Permitted,
            caps::CapSet::Effective,
            caps::CapSet::Inheritable,
            caps::CapSet::Ambient,
        ] {
            assert!(caps::read(None, set).unwrap().is_empty(), "{set:?}");
        }
        drop(bound);
    }

    #[test]
    #[cfg_attr(miri, ignore = "sockets: native runs keep it")]
    fn a_listener_not_bound_or_without_its_certificate_is_refused() {
        let bad = [Listener {
            bind: "no-such-host.invalid:80",
            ..listener("bad", Tls::Plain)
        }];
        assert!(matches!(
            bind(&bad),
            Err(RunError::Bind { listener, .. }) if listener == "bad"
        ));
        let missing = [listener(
            "nocert",
            Tls::Server {
                cert: "/nonexistent/cert.pem",
                key: "/nonexistent/key.pem",
            },
        )];
        assert!(matches!(
            bind(&missing),
            Err(RunError::Certs { listener, .. }) if listener == "nocert"
        ));
    }
}
