//! npro-io: how a sans-IO npro connection meets sockets, timers and the
//! scheduler the user has.
//!
//! The protocol crates take bytes and time and give bytes and events; they
//! never call IO.  This crate carries a connection between them and the
//! IO, as `docs/io-model.md` lays out:
//!
//! - [`conn`]: the connection, whichever its role, h1 server or client, ws
//!   either end, or raw, and its changes of role, h1 to ws or raw;
//! - [`driver`]: what carries it, keeping its buffers, close stages and
//!   deadlines, and saying what IO it wants;
//! - [`raw`]: the raw role, bytes as they are both ways;
//! - [`tls`]: the record layer the driver keeps tls behind, a trait a tls
//!   stack is bound to it by;
//! - [`host`]: what an adapter drives when it carries many connections by
//!   id, as npro-ss does;
//! - `threads`, with the `std` feature: the first adapter, a host's
//!   connections over std's sockets, a reader and a writer thread each;
//!
//! with the adapters for mio, tokio and embassy to come.  Without
//! features it is `no_std`, and does no IO itself.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "std")]
extern crate std;

pub mod conn;
pub mod driver;
pub mod host;
pub mod raw;
#[cfg(feature = "std")]
pub mod threads;
pub mod tls;
