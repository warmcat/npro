//! The certificate distribution client against a server the test plays,
//! over mTLS on this machine: a chain and key fetched and installed
//! under the pki directory, a listener whose certificate they are
//! bound before they came, and on the next connect the hash of what is
//! installed said first and the server's "unchanged" taken.

#![expect(
    unused_crate_dependencies,
    reason = "an integration test sees all of its crate's dependencies; this one uses what the client and the server it plays need"
)]

// held to clippy's rules for tests
#[cfg(test)]
mod certdist {
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use npro_certdist::hash;
    use npro_cli::certdist::{Dist, Server};
    use npro_cli::front::{App, Front, Logs, Services, act};
    use npro_cli::random::ProviderRandom;
    use npro_cli::runner::{Identities, Streams, bind_awaiting};
    use npro_cli::tls;
    use npro_core::time::Instant;
    use npro_h1::server::Config;
    use npro_io::driver::{Buffers, NetBuffers};
    use npro_io::threads::{self, Jobs, Listening, Stop, Workers};
    use npro_io::tls::rustls::RustlsAny;
    use npro_ss::event::{End, Filled, Kind};
    use npro_ss::id::{ListenerId, StreamId};
    use npro_ss::policy::{Deflate, Listener, Match, Payload, Route, Tls, Vhost, Ws, WsServer};
    use npro_ss::ss::{ConnStorage, Slot, Ss};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::server::WebPkiClientVerifier;
    use rustls::{RootCertStore, ServerConfig};

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

    /// What the server distributes: the test leaf chain and its key, as
    /// PEM, which the client's listener then serves.
    fn distributed() -> (String, String) {
        (
            pem("CERTIFICATE", &der("leaf.der")) + &pem("CERTIFICATE", &der("ca.der")),
            pem("PRIVATE KEY", &der("leaf-key.der")),
        )
    }

    /// The server the test plays: tls asking the client who it is, the
    /// test CA its judge, and the ws route the protocol is on.
    fn server_config() -> Arc<ServerConfig> {
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(der("ca.der"))).unwrap();
        let verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), npro_aws_lc::provider())
                .build()
                .unwrap();
        let mut c = ServerConfig::builder_with_provider(npro_aws_lc::provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![
                    CertificateDer::from(der("leaf.der")),
                    CertificateDer::from(der("ca.der")),
                ],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der("leaf-key.der"))),
            )
            .unwrap();
        c.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(c)
    }

    const PROTOCOLS: [&[u8]; 1] = [b"lws-cert-dist-server"];
    const ROUTES: [Route<'static>; 1] = [Route {
        path: "/",
        matching: Match::Prefix,
        to: "dist",
        ws: Ws::Taken(WsServer {
            protocols: &PROTOCOLS,
            default: Some(0),
            payload: Payload::Text,
            deflate: Deflate::Off,
        }),
        headers: &[],
    }];
    const VHOSTS: [Vhost<'static>; 1] = [Vhost {
        name: "localhost",
        routes: &ROUTES,
        headers: &[],
        not_found: None,
    }];
    fn server_listener() -> Listener<'static> {
        Listener {
            name: "dist",
            bind: "127.0.0.1:0",
            tls: Tls::Server {
                cert: "made in the test",
                key: "made in the test",
            },
            h1: Config::default(),
            vhosts: &VHOSTS,
        }
    }

    /// A served link's state: what it has to send, what it heard, and
    /// whether it was answered.
    #[derive(Default)]
    struct Link {
        out: Vec<u8>,
        at: usize,
        heard: Vec<u8>,
        answered: bool,
    }

    type ServerSs<'s> = Ss<'s, Link, Vec<u8>, ProviderRandom, RustlsAny>;

    fn server_slots() -> Vec<Slot<Link, Vec<u8>, ProviderRandom, RustlsAny>> {
        (0..4)
            .map(|_| {
                Slot::new(ConnStorage {
                    h1: npro_h1::Storage {
                        table: vec![0; 4096],
                        out: vec![0; 2048],
                    },
                    bufs: Buffers {
                        rx: vec![0; 16384],
                        tx: vec![0; 16384],
                        inflate: Vec::new(),
                    },
                    net: NetBuffers {
                        rx: vec![0; 20480],
                        tx: vec![0; 20480],
                    },
                })
            })
            .collect()
    }

    /// The message the server sends: the pair, or unchanged, as C
    /// composes it.
    fn message(fullchain: &str, privkey: &str) -> Vec<u8> {
        let esc = |s: &str| s.replace('\n', "\\n");
        format!(
            "{{\"subdomain\":\"npro.rs\",\"fullchain\":\"{}\",\"privkey\":\"{}\"}}",
            esc(fullchain),
            esc(privkey)
        )
        .into_bytes()
    }

    /// The server's turn: a link upgraded is answered at once with the
    /// pair, unless the hash the client says first is the pair's, when
    /// it is answered unchanged.  What each link said is kept for the
    /// test.
    fn serve_dist<'s>(
        ss: &mut ServerSs<'s>,
        now: Instant,
        jobs: &Jobs<'_, ServerSs<'s>>,
        heard: &Mutex<Vec<String>>,
        pair: &(String, String),
    ) {
        let mut to_send: Vec<(StreamId, Vec<u8>)> = Vec::new();
        while let Some(ev) = ss.poll_event(now) {
            let (stream, link): (StreamId, &mut Link) = (ev.stream, ev.user);
            match ev.kind {
                // as C: the client has 500ms to say its hash, then the
                // pair is sent anyway
                Kind::ServerUpgrade { .. } => {
                    let answer = message(&pair.0, &pair.1);
                    jobs.after(
                        Duration::from_millis(500),
                        move |streams: &mut ServerSs<'s>, _| {
                            let len = u64::try_from(answer.len()).unwrap();
                            if let Ok(served) = streams.user(stream) {
                                if served.answered {
                                    return;
                                }
                                served.answered = true;
                                served.out = answer;
                                served.at = 0;
                            }
                            streams.request_tx_len(stream, len).unwrap();
                        },
                    );
                }
                Kind::Rx { data, end } => {
                    link.heard.extend_from_slice(data);
                    if end == End::Last {
                        let said = String::from_utf8_lossy(&link.heard).into_owned();
                        heard.lock().unwrap().push(said.clone());
                        link.heard.clear();
                        let expected = hash::of(pair.0.as_bytes());
                        let mut m = [0u8; hash::MESSAGE_LEN];
                        hash::message(&expected, &mut m);
                        let answer = if said.as_bytes() == m {
                            message("", "")
                        } else {
                            message(&pair.0, &pair.1)
                        };
                        to_send.push((stream, answer));
                    }
                }
                Kind::Tx(tx) => {
                    tx.fill(|buf| {
                        let rest = &link.out[link.at..];
                        let n = rest.len().min(buf.len());
                        buf[..n].copy_from_slice(&rest[..n]);
                        link.at = link.at.checked_add(n).unwrap();
                        if link.at >= link.out.len() {
                            Filled::Last(n)
                        } else {
                            Filled::More(n)
                        }
                    });
                }
                Kind::ServerTxn(_)
                | Kind::UpgradeRefused(_)
                | Kind::ClientUpgraded { .. }
                | Kind::NotUpgraded { .. }
                | Kind::ServerTxnEnd(_)
                | Kind::Response(_)
                | Kind::ConnectFailed
                | Kind::Pong
                | Kind::PeerClose { .. }
                | Kind::Disconnected => {}
            }
        }
        for (stream, answer) in to_send {
            let len = u64::try_from(answer.len()).unwrap();
            if let Ok(link) = ss.user(stream) {
                link.answered = true;
                link.out = answer;
                link.at = 0;
            }
            ss.request_tx_len(stream, len).unwrap();
        }
    }

    /// Runs the client for `secs`, its link to `port`, installing under
    /// `pki`, its listener serving `pki`'s certificate.
    fn run_client(port: u16, pki: &Path, identity: &(PathBuf, PathBuf, PathBuf), secs: u64) {
        let cert: &'static str = Dist::fullchain_path(pki, "npro.rs")
            .to_str()
            .unwrap()
            .to_owned()
            .leak();
        let key: &'static str = Dist::privkey_path(pki, "npro.rs")
            .to_str()
            .unwrap()
            .to_owned()
            .leak();
        let listeners = [Listener {
            name: "https",
            bind: "127.0.0.1:0",
            tls: Tls::Server { cert, key },
            h1: Config::default(),
            vhosts: &VHOSTS,
        }];
        let mut identities = Identities::new();
        identities.add(
            "npro.rs",
            tls::identity(&identity.0, &identity.1, &identity.2).unwrap(),
        );
        let bound = bind_awaiting(&listeners, &["https"])
            .unwrap()
            .with_identities(identities);
        let mut app = App {
            services: Services { by_name: &[] },
            logs: Logs::none(),
            dist: Some(Dist::new(
                Server::parse(&format!("wss://localhost:{port}")).unwrap(),
                pki.to_path_buf(),
                &["npro.rs"],
                ProviderRandom::new(),
            )),
        };
        let stop = Stop::new();
        thread::scope(|scope| {
            let served = scope.spawn(|| {
                bound.serve(
                    4,
                    |ss: &mut Streams<'_, Front>, now, jobs| act(&mut app, ss, now, jobs),
                    Workers::default(),
                    &stop,
                )
            });
            thread::sleep(Duration::from_secs(secs));
            stop.stop();
            served.join().unwrap().unwrap();
        });
    }

    #[test]
    #[cfg_attr(miri, ignore = "sockets, tls and threads: native runs keep it")]
    fn the_client_fetches_installs_and_says_the_hash_next_time() {
        let dir = std::env::temp_dir().join(format!("npro-certdist-test-{}", std::process::id()));
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).unwrap();
        // the identity: the CA, and the client leaf and key, as PEM files
        let ca = dir.join("ca.pem");
        let client = dir.join("client.pem");
        let client_key = dir.join("client-key.pem");
        std::fs::write(&ca, pem("CERTIFICATE", &der("ca.der"))).unwrap();
        std::fs::write(&client, pem("CERTIFICATE", &der("client.der"))).unwrap();
        std::fs::write(&client_key, pem("PRIVATE KEY", &der("client-key.der"))).unwrap();
        let identity = (ca, client, client_key);
        let pki = dir.join("pki");
        let pair = distributed();

        // the server the test plays
        let listening = threads::bind("127.0.0.1:0").unwrap();
        let port = listening.local_addr().unwrap().unwrap().port();
        let heard = Mutex::new(Vec::new());
        let config = server_config();
        let stop = Stop::new();
        let listeners = [server_listener()];
        let mut slots = server_slots();
        let ss = Ss::new(&listeners, &mut slots).unwrap();
        thread::scope(|scope| {
            let (heard, pair, stop, config) = (&heard, &pair, &stop, &config);
            let server = scope.spawn(move || {
                let make = |_: ListenerId| {
                    npro_aws_lc::server(Arc::clone(config))
                        .ok()
                        .map(RustlsAny::Server)
                };
                threads::serve(
                    ss,
                    vec![(ListenerId::new(0), clone_listening(&listening))],
                    &make,
                    |ss: &mut ServerSs<'_>, now, jobs| serve_dist(ss, now, jobs, heard, pair),
                    Workers::default(),
                    stop,
                )
            });

            // a failed assertion must still stop the server, or the scope
            // waits for it for ever
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                // nothing installed: the client connects, says nothing first,
                // is sent the pair, and installs it
                run_client(port, &pki, &identity, 3);
                assert_eq!(
                    std::fs::read_to_string(Dist::fullchain_path(&pki, "npro.rs")).unwrap(),
                    pair.0
                );
                assert_eq!(
                    std::fs::read_to_string(Dist::privkey_path(&pki, "npro.rs")).unwrap(),
                    pair.1
                );
                assert_eq!(
                    heard.lock().unwrap().len(),
                    0,
                    "nothing to say the first time"
                );

                // next time, the hash of what is installed goes first, and the
                // server answers unchanged: the files are as they were
                let before: Vec<_> = std::fs::read_dir(pki.join("npro.rs"))
                    .unwrap()
                    .map(|e| e.unwrap().file_name())
                    .collect();
                run_client(port, &pki, &identity, 3);
                let said = heard.lock().unwrap().clone();
                let mut expected = [0u8; hash::MESSAGE_LEN];
                hash::message(&hash::of(pair.0.as_bytes()), &mut expected);
                assert_eq!(
                    said,
                    [String::from_utf8(expected.to_vec()).unwrap()],
                    "the hash said on the second connect"
                );
                let after: Vec<_> = std::fs::read_dir(pki.join("npro.rs"))
                    .unwrap()
                    .map(|e| e.unwrap().file_name())
                    .collect();
                assert_eq!(before.len(), after.len(), "unchanged installs nothing");
            }));
            stop.stop();
            server.join().unwrap();
            if let Err(e) = outcome {
                std::panic::resume_unwind(e);
            }
        });
        drop(std::fs::remove_dir_all(&dir));
    }

    fn clone_listening(l: &Listening) -> Listening {
        match l {
            Listening::Tcp(t) => Listening::Tcp(t.try_clone().unwrap()),
            #[cfg(unix)]
            Listening::Unix(u) => Listening::Unix(u.try_clone().unwrap()),
        }
    }
}
