//! npro: safe, sans-IO network protocols.
//!
//! npro is the Rust port of the sansIO half of
//! [libwebsockets](https://libwebsockets.org): the h1, h2, h3, ws and wt
//! protocols as state machines that take bytes and time as input and
//! produce bytes and events, with no sockets, threads or clock of their own.
//!
//! This facade re-exports the protocol crates behind features as they are
//! written.  Nothing is usable yet; see <https://npro.rs> for the status.

#![no_std]
#![forbid(unsafe_code)]
