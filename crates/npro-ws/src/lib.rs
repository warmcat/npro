//! npro-ws: websockets for npro, sans-IO.
//!
//! The port of C libwebsockets' ws role (`lib/sansio/ws`):
//!
//! - [`handshake`]: a server's checks of an upgrade request, and its 101;
//! - [`conn`]: a ws connection, its frames in and out, and its close.
//!
//! The client's handshake comes next, in phase 1e of the port plan.

#![no_std]
#![forbid(unsafe_code)]

pub mod conn;
pub mod handshake;
