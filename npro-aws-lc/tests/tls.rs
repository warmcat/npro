//! npro-io's rustls record layer, with a real provider: an h1 client's
//! driver and an h1 server's, back to back over in-memory sockets, doing
//! the handshake and the exchange as they would over TCP.
//!
//! The certificates are in `tests/certs`, made by its `make.sh`: a test CA,
//! and a leaf for `localhost` it signs.

use std::sync::Arc;

use npro_core::random::Random;
use npro_core::random::Unavailable;
use npro_core::time::Instant;
use npro_h1::client::{Client, Connection, Event as H1c, Request, Scheme};
use npro_h1::server::{Config, Event as H1s, Response, Server, TxSource};
use npro_io::conn::{Conn, Event, RoleMut};
use npro_io::driver::{Buffers, Driver, NetBuffers, Outcome, Want};
use npro_io::tls::RecordLayer;
use npro_io::tls::rustls::{RustlsClient, RustlsServer};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig, SupportedProtocolVersion};

const T0: Instant = Instant::from_micros(1_000_000);

/// No ws client here: its random is never drawn.
#[derive(Debug)]
struct NoRandom;

impl Random for NoRandom {
    fn fill(&mut self, _: &mut [u8]) -> Result<(), Unavailable> {
        Err(Unavailable)
    }
}

type C<T> = Driver<Vec<u8>, NoRandom, Vec<u8>, T>;

fn ca() -> CertificateDer<'static> {
    CertificateDer::from(include_bytes!("certs/ca.der").to_vec())
}

fn server_config(alpn: &[&[u8]], v: &[&'static SupportedProtocolVersion]) -> Arc<ServerConfig> {
    let leaf = CertificateDer::from(include_bytes!("certs/leaf.der").to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        include_bytes!("certs/leaf-key.der").to_vec(),
    ));
    let mut c = ServerConfig::builder_with_provider(npro_aws_lc::provider())
        .with_protocol_versions(v)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![leaf, ca()], key)
        .unwrap();
    c.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(c)
}

fn client_config(alpn: &[&[u8]], v: &[&'static SupportedProtocolVersion]) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(ca()).unwrap();
    let mut c = ClientConfig::builder_with_provider(npro_aws_lc::provider())
        .with_protocol_versions(v)
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    c.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(c)
}

fn bufs() -> (Buffers<Vec<u8>>, NetBuffers<Vec<u8>>) {
    // a record's 16KiB, and its overhead for the records
    (
        Buffers {
            rx: vec![0; 17 * 1024],
            tx: vec![0; 17 * 1024],
            inflate: Vec::new(),
        },
        NetBuffers {
            rx: vec![0; 18 * 1024],
            tx: vec![0; 18 * 1024],
        },
    )
}

fn client_driver(layer: RustlsClient) -> C<RustlsClient> {
    let c = Client::new(
        vec![0u8; 1024],
        Request {
            method: b"GET",
            path: b"/",
            host: Some(b"localhost"),
            origin: None,
            scheme: Scheme::Https,
            no_cache: false,
            connection: Connection::Close,
        },
    )
    .unwrap();
    let (b, n) = bufs();
    Driver::with_tls(Conn::h1_client(c), b, layer, n, T0)
}

fn server_driver(layer: RustlsServer) -> C<RustlsServer> {
    let s = Server::new(vec![0u8; 1024], Config::default(), T0).unwrap();
    let (b, n) = bufs();
    Driver::with_tls(Conn::h1_server(s), b, layer, n, T0)
}

/// The server's payload.
struct Text(Vec<u8>);

impl TxSource for Text {
    fn fill(&mut self, buf: &mut [u8]) -> usize {
        let n = self.0.len().min(buf.len());
        buf[..n].copy_from_slice(&self.0[..n]);
        self.0.drain(..n);
        n
    }
}

/// Moves what `from` writes into `to`, as a socket would; what went.
fn carry<A: RecordLayer, B: RecordLayer>(
    from: &mut C<A>,
    src: &mut Text,
    to: &mut C<B>,
    sink: &mut Text,
) -> Vec<u8> {
    let mut went = Vec::new();
    loop {
        let Want::Io(io) = from.want(T0, src) else {
            return went;
        };
        let Some(w) = io.write else {
            return went;
        };
        let bytes = w.to_vec();
        from.write_done(T0, bytes.len());
        let mut at = 0;
        while at < bytes.len() {
            let n = to.received(T0, &bytes[at..]);
            if n == 0 {
                // the peer holds what it has: let it take some
                let Want::Io(_) = to.want(T0, sink) else {
                    return went;
                };
                continue;
            }
            at += n;
        }
        went.extend_from_slice(&bytes);
    }
}

/// What a GET over tls came to: the body, the wire's bytes, and how each
/// end was released.
struct Run {
    body: Vec<u8>,
    wire: Vec<u8>,
    client: Option<Outcome>,
    server: Option<Want<'static>>,
    alpn: Option<Vec<u8>>,
}

fn get(mut c: C<RustlsClient>, mut s: C<RustlsServer>) -> Run {
    let (mut csrc, mut ssrc) = (Text(Vec::new()), Text(b"ok over tls".to_vec()));
    let (mut wire, mut body) = (Vec::new(), Vec::new());
    for _ in 0..100 {
        wire.extend(carry(&mut c, &mut csrc, &mut s, &mut ssrc));
        while let Some(mut step) = s.poll_rx(T0) {
            if step.event() == Some(Event::H1Server(H1s::Request)) {
                let RoleMut::H1Server(srv) = step.conn().role_mut() else {
                    panic!("not h1");
                };
                srv.respond(Response {
                    status: 200,
                    content_type: None,
                    content_length: None,
                })
                .unwrap();
                step.request_write();
            }
        }
        wire.extend(carry(&mut s, &mut ssrc, &mut c, &mut csrc));
        if ssrc.0.is_empty() {
            if let RoleMut::H1Server(srv) = s.conn().role_mut() {
                srv.complete(T0);
            }
        }
        while let Some(step) = c.poll_rx(T0) {
            if let Some(Event::H1Client(H1c::Body(b))) = step.event() {
                body.extend_from_slice(b);
            }
        }
    }
    let alpn = c.tls().and_then(RecordLayer::alpn).map(<[u8]>::to_vec);
    let client = match c.want(T0, &mut csrc) {
        Want::Release(o) => Some(o),
        Want::Io(_) | Want::HalfClose => None,
    };
    let server = match s.want(T0, &mut ssrc) {
        Want::Release(o) => Some(Want::Release(o)),
        Want::HalfClose => Some(Want::HalfClose),
        Want::Io(_) => None,
    };
    Run {
        body,
        wire,
        client,
        server,
        alpn,
    }
}

fn exchange(v: &[&'static SupportedProtocolVersion]) -> Run {
    let alpn: &[&[u8]] = &[b"http/1.1"];
    let name = ServerName::try_from("localhost").unwrap();
    let c = npro_aws_lc::client(client_config(alpn, v), name).unwrap();
    let s = npro_aws_lc::server(server_config(alpn, v)).unwrap();
    get(client_driver(c), server_driver(s))
}

fn assert_good(r: &Run) {
    assert_eq!(r.body, b"ok over tls");
    assert_eq!(r.alpn.as_deref(), Some(&b"http/1.1"[..]));
    // the server's close_notify ended the body; the client goes, the
    // server half-closes to wait for the client's FIN
    assert_eq!(r.client, Some(Outcome::Delivered));
    assert!(matches!(r.server, Some(Want::HalfClose)));
    assert!(!r.wire.windows(5).any(|w| w == b"GET /"));
    assert!(!r.wire.windows(11).any(|w| w == b"ok over tls"));
}

#[test]
fn an_h1_exchange_goes_over_tls_1_3() {
    assert_good(&exchange(&[&rustls::version::TLS13]));
}

#[test]
fn an_h1_exchange_goes_over_tls_1_2() {
    assert_good(&exchange(&[&rustls::version::TLS12]));
}

#[test]
fn a_server_not_who_it_must_be_is_refused() {
    let alpn: &[&[u8]] = &[b"http/1.1"];
    let v = &[&rustls::version::TLS13];
    let name = ServerName::try_from("not-localhost").unwrap();
    let c = npro_aws_lc::client(client_config(alpn, v), name).unwrap();
    let s = npro_aws_lc::server(server_config(alpn, v)).unwrap();
    let r = get(client_driver(c), server_driver(s));
    assert_eq!(r.body, b"");
    assert_eq!(r.client, Some(Outcome::Dropped));
}
