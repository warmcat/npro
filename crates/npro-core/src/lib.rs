//! The sans-IO core of npro.
//!
//! What the protocol crates share: the connection's state machines, time
//! and random as inputs rather than things read from the platform, and the
//! substrate the protocols are built from.  Nothing here owns a socket, a
//! thread or a clock; the IO side, or a test, supplies all of them.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod base64;
pub mod random;
pub mod sha1;
pub mod utf8;
