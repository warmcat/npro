//! npro-h1: h1 for npro, sans-IO.
//!
//! The port of C libwebsockets' h1 parsing (`lib/sansio/http/parsers.c`):
//!
//! - [`head`]: a request or response head, parsed as it arrives, with C's
//!   limits and refusals, into
//! - [`table`]: where the head's headers are kept, in caller-owned storage,
//!   found by
//! - [`token`]: the headers lws knows by name;
//! - [`chunked`]: the chunked transfer coding's framing, shared by client
//!   and server;
//! - [`fields`]: what a few header values mean, as C reads them;
//! - [`server`]: an h1 server connection's transactions.
//!
//! The h1 client's transactions come next, in phase 1d of the port plan.

#![no_std]
#![forbid(unsafe_code)]

pub mod chunked;
pub mod fields;
pub mod head;
mod own;
pub mod server;
pub mod table;
pub mod token;
