//! npro-io: how a sans-IO npro connection meets sockets, timers and the
//! scheduler the user has.
//!
//! The protocol crates take bytes and time and give bytes and events; they
//! never call IO.  This crate carries a connection between them and the
//! IO, as `docs/io-model.md` lays out:
//!
//! - [`conn`]: the connection, whichever its role, h1 server or client, ws
//!   either end, and its changes of role, h1 to ws;
//! - [`driver`]: what carries it, keeping its buffers, close stages and
//!   deadlines, and saying what IO it wants;
//!
//! with tls in the driver, and the adapters for threads, mio, tokio and
//! embassy, to come.
//! Without features it is `no_std`, and does no IO itself.

#![no_std]
#![forbid(unsafe_code)]

pub mod conn;
pub mod driver;
