//! npro-ws: websockets for npro, sans-IO.
//!
//! The port of C libwebsockets' ws role (`lib/sansio/ws`):
//!
//! - [`handshake`]: a server's checks of an upgrade request and its 101,
//!   and a client's key, its request's upgrade lines and its checks of the
//!   server's response;
//! - [`conn`]: a ws connection, either end, its frames in and out, and its
//!   close;
//! - `pmd`, with the opt-in feature of that name: permessage-deflate, its
//!   negotiation and its compression, which needs `alloc`.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "pmd")]
extern crate alloc;

pub mod conn;
pub mod handshake;
#[cfg(feature = "pmd")]
pub mod pmd;
