//! npro-cli: npro's utility, `npro`, and its runner.
//!
//! The utility is one program, server and client, whose server is
//! npro.rs' (docs/ss-design.md).  What it does is applications and
//! services, which know nothing of what carries them; this crate is what
//! carries them:
//!
//! - [`runner`]: the policy's listeners bound, the process' privileges
//!   dropped, and the streams carried by npro-io's threads adapter, with
//!   rustls over aws-lc for tls listeners;
//! - [`front`]: the server's application, answering each request from the
//!   service its route names: files, the proxy, a redirect, or a script;
//! - [`certdist`]: the certificate distribution client, its links kept
//!   up from the front, and what the server sends installed;
//! - [`policy`]: the policy from JSON, its layers merged, made into the
//!   types the runner and the front take;
//! - [`tls`]: a listener's certificate and key, by path, made into a
//!   config again when they change on disk;
//! - [`privileges`]: every capability dropped once the listeners are bound;
//! - [`random`]: npro's random from the tls provider's.
//!
//! The command, `npro`, is `src/main.rs`: `npro serve` serves everything
//! its policy says.

#![forbid(unsafe_code)]

pub mod certdist;
pub mod front;
pub mod policy;
pub mod privileges;
pub mod random;
pub mod runner;
pub mod tls;
