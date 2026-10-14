//! npro-ss: npro's Secure Streams, SS2.
//!
//! A stream is the application's object: payload in, payload out, and
//! what happened to it as information.  What it is carried over (the
//! address, tls, the protocol) is its streamtype's, from the policy, so an
//! application is the same code whatever is underneath it.  This is C's
//! Secure Streams, as `docs/ss-design.md` lays it out, sans-IO as npro's
//! protocol crates are: it holds the streams and their connections'
//! drivers, does no IO and reads no clock, and asks the adapter for what it
//! cannot do.
//!
//! - [`policy`]: what the policy gives it, as Rust types;
//! - [`ss`]: the streams and their connections, driven by the adapter on
//!   one side and the application on the other;
//! - [`event`]: what a stream is told, and the handles some events lend;
//! - [`id`]: the ids streams, connections and listeners are named by.
//!
//! So far it is the server's half: listeners, each with its vhosts and
//! their routes, the streams accepted on them, a request's head in, routed
//! to its vhost and route, and its response out, and ws taken on as the
//! route says.  Client streams come next.
//!
//! ```
//! use npro_core::random::SeededRandom;
//! use npro_core::time::Instant;
//! use npro_h1::Storage;
//! use npro_h1::server::Config;
//! use npro_io::driver::{Buffers, NetBuffers, Want};
//! use npro_ss::event::{Filled, Kind, Response};
//! use npro_ss::id::ListenerId;
//! use npro_ss::policy::{Listener, Match, Route, Tls, Vhost, Ws};
//! use npro_ss::ss::{ConnStorage, Slot, Ss};
//!
//! let listeners = [Listener {
//!     name: "www",
//!     bind: "[::]:8080",
//!     tls: Tls::Plain,
//!     h1: Config::default(),
//!     vhosts: &[Vhost {
//!         name: "example.com",
//!         routes: &[Route {
//!             path: "/",
//!             matching: Match::Prefix,
//!             to: "hello",
//!             ws: Ws::NotTaken,
//!             headers: &[],
//!         }],
//!         headers: &[(b"x-frame-options", b"deny")],
//!         not_found: None,
//!     }],
//! }];
//! let storage = || ConnStorage {
//!     h1: Storage { table: vec![0u8; 1024], out: vec![0u8; 512] },
//!     bufs: Buffers { rx: vec![0u8; 1024], tx: vec![0u8; 1024], inflate: Vec::new() },
//!     net: NetBuffers { rx: Vec::new(), tx: Vec::new() },
//! };
//! let mut slots: Vec<Slot<(), Vec<u8>, SeededRandom>> = (0..4).map(|_| Slot::new(storage())).collect();
//! let mut ss = Ss::new(&listeners, &mut slots)?;
//! let now = Instant::from_micros(1_000_000);
//!
//! // the adapter accepted a socket, and reads a request from it
//! let conn = ss.accepted(now, ListenerId::new(0), None)?;
//! let Want::Io(io) = ss.want(now, conn)? else { unreachable!() };
//! let req = b"GET /hello HTTP/1.1\r\nHost: x\r\n\r\n";
//! io.read.unwrap()[..req.len()].copy_from_slice(req);
//! ss.read_done(now, conn, req.len())?;
//!
//! // the application answers what its streams are told
//! while let Some(ev) = ss.poll_event(now) {
//!     let stream = ev.stream;
//!     match ev.kind {
//!         Kind::ServerTxn(mut txn) => {
//!             assert_eq!(txn.path(), Some(&b"/hello"[..]));
//!             assert_eq!(txn.route().map(|r| (r.route.to, r.rest)), Some(("hello", &b"hello"[..])));
//!             txn.respond(Response {
//!                 status: 200,
//!                 content_type: Some(b"text/plain"),
//!                 content_length: Some(2),
//!                 headers: &[],
//!             })?;
//!             ss.request_tx(stream)?;
//!         }
//!         Kind::Tx(tx) => {
//!             tx.fill(|buf| {
//!                 buf[..2].copy_from_slice(b"hi");
//!                 Filled::Last(2)
//!             });
//!         }
//!         _ => {}
//!     }
//! }
//!
//! // and the adapter writes what the connection has
//! let Want::Io(io) = ss.want(now, conn)? else { unreachable!() };
//! assert_eq!(
//!     io.write.unwrap(),
//!     b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 2\r\n\
//!       x-frame-options: deny\r\n\r\nhi"
//! );
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

#![no_std]
#![forbid(unsafe_code)]

pub mod event;
pub mod id;
pub mod policy;
pub mod ss;
