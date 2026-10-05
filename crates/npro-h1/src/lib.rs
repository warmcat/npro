//! npro-h1: h1 for npro, sans-IO.
//!
//! The port of C libwebsockets' h1 (`lib/sansio/http`):
//!
//! - [`head`]: a request or response head, parsed as it arrives, with C's
//!   limits and refusals, into
//! - [`table`]: where the head's headers are kept, in caller-owned storage,
//!   found by
//! - [`token`]: the headers lws knows by name;
//! - [`chunked`]: the chunked transfer coding's framing, shared by client
//!   and server;
//! - [`fields`]: what a few header values mean, as C reads them;
//! - [`server`]: an h1 server connection's transactions;
//! - [`client`]: an h1 client connection's transaction.

#![no_std]
#![forbid(unsafe_code)]

pub mod chunked;
pub mod client;
pub mod fields;
pub mod head;
mod own;
pub mod server;
pub mod table;
pub mod token;
