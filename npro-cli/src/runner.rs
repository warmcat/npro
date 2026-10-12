//! The runner: the policy's listeners bound, the process' privileges
//! dropped, and the streams carried by the threads adapter with rustls
//! over aws-lc.
//!
//! It is the only code that names a loop and a tls provider
//! (docs/ss-design.md, "The policy picks the loop and the tls"); what it
//! runs, the application, is given the streams and knows neither.  It
//! goes in two steps, so that what needs privilege is done, and the
//! privilege dropped, before anything is accepted:
//!
//! 1. [`bind`]: every listener bound, every tls listener's certificate and
//!    key loaded, then every capability dropped;
//! 2. [`Bound::serve`]: the streams made, in slots sized for tls, and
//!    carried until stopped.

use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Mutex, PoisonError};

use npro_core::time::Instant;
use npro_io::driver::{Buffers, NetBuffers};
use npro_io::threads::{self, Listening, Stop};
use npro_io::tls::rustls::RustlsServer;
use npro_ss::id::ListenerId;
use npro_ss::policy::{Listener, Tls};
use npro_ss::ss::{ConnStorage, NewError, Slot, Ss};

use crate::privileges::{self, Kept};
use crate::random::ProviderRandom;
use crate::tls::{CertError, Certs};

/// The streams as the runner makes them: each application's `U`, buffers
/// of its own, the provider's random, and rustls.
pub type Streams<'s, U> = Ss<'s, U, Vec<u8>, ProviderRandom, RustlsServer>;

/// Each connection's buffers, by what they hold.  tls opens and seals a
/// record only whole: 16KiB of payload, and up to 2KiB more on the wire.
mod size {
    /// The h1 header table.
    pub(super) const TABLE: usize = 8 * 1024;
    /// What the h1 role composes of its own: a response's head, which
    /// carries the listener's headers (npro.rs' are over a kilobyte).
    pub(super) const OUT: usize = 4 * 1024;
    /// Plaintext, each way: a tls record's payload.
    pub(super) const PLAIN: usize = 17 * 1024;
    /// tls records, each way: one, with its overhead.
    pub(super) const RECORDS: usize = 18 * 1024;
    /// Where a deflated ws message is inflated.
    pub(super) const INFLATE: usize = npro_ws::pmd::RX_CHUNK;
}

/// Why the runner stopped before serving.
#[derive(Debug)]
pub enum RunError {
    /// A listener could not be bound.
    Bind {
        /// Its name in the policy.
        listener: String,
        /// Why.
        error: io::Error,
    },
    /// A tls listener's certificate and key did not load.
    Certs {
        /// Its name in the policy.
        listener: String,
        /// Why.
        error: CertError,
    },
    /// The capabilities could not be dropped.
    Privileges(Kept),
    /// The policy, or the storage made for it, was refused.
    Policy(NewError),
}

impl core::fmt::Display for RunError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Bind { listener, error } => write!(f, "{listener}: bind: {error}"),
            Self::Certs { listener, error } => write!(f, "{listener}: {error}"),
            Self::Privileges(k) => write!(f, "{k}"),
            Self::Policy(e) => write!(f, "policy: {e}"),
        }
    }
}

impl core::error::Error for RunError {}

/// The policy's listeners, bound, and their certificates loaded, with the
/// process' privileges dropped: [`bind`].
#[derive(Debug)]
pub struct Bound<'p> {
    listeners: &'p [Listener<'p>],
    sockets: Vec<Listening>,
    certs: Vec<Option<Certs>>,
}

/// Binds each of `listeners` where it says, loads each tls one's
/// certificate and key, then drops every capability the process has.
/// Call it before starting any thread: capabilities are each thread's,
/// and those started after have none.
///
/// # Errors
///
/// [`RunError`]: a listener not bound, a certificate not loaded, or a
/// capability not dropped.
pub fn bind<'p>(listeners: &'p [Listener<'p>]) -> Result<Bound<'p>, RunError> {
    let now = std::time::Instant::now();
    let mut sockets = Vec::with_capacity(listeners.len());
    let mut certs = Vec::with_capacity(listeners.len());
    for l in listeners {
        sockets.push(threads::bind(l.bind).map_err(|error| RunError::Bind {
            listener: l.name.to_owned(),
            error,
        })?);
        certs.push(match l.tls {
            Tls::Plain => None,
            Tls::Server { cert, key } => Some(
                Certs::load(Path::new(cert), Path::new(key), now).map_err(|error| {
                    RunError::Certs {
                        listener: l.name.to_owned(),
                        error,
                    }
                })?,
            ),
        });
    }
    privileges::drop_all().map_err(RunError::Privileges)?;
    Ok(Bound {
        listeners,
        sockets,
        certs,
    })
}

impl Bound<'_> {
    /// Where the listener `id` is bound, if it is TCP: what a port of 0
    /// came to.
    #[must_use]
    pub fn local_addr(&self, id: ListenerId) -> Option<SocketAddr> {
        let i = usize::try_from(id.index()).ok()?;
        self.sockets.get(i)?.local_addr().ok().flatten()
    }

    /// Carries the listeners' streams, in `slots` slots, until `stop` is
    /// stopped, `app` acting on them after anything changed, as npro-io's
    /// threads adapter gives it them.  An accepted stream starts with `U`'s
    /// default.
    ///
    /// # Errors
    ///
    /// [`RunError::Policy`], if the policy was refused.
    pub fn serve<U, A>(self, slots: usize, mut app: A, stop: &Stop) -> Result<(), RunError>
    where
        U: Default + Send,
        A: for<'s> FnMut(&mut Streams<'s, U>, Instant) + Send,
    {
        let tls = self
            .listeners
            .iter()
            .any(|l| matches!(l.tls, Tls::Server { .. }));
        let records = if tls { size::RECORDS } else { 0 };
        let mut storage: Vec<Slot<U, Vec<u8>, ProviderRandom, RustlsServer>> = (0..slots)
            .map(|_| {
                Slot::new(ConnStorage {
                    h1: npro_h1::Storage {
                        table: vec![0; size::TABLE],
                        out: vec![0; size::OUT],
                    },
                    bufs: Buffers {
                        rx: vec![0; size::PLAIN],
                        tx: vec![0; size::PLAIN],
                        inflate: vec![0; size::INFLATE],
                    },
                    net: NetBuffers {
                        rx: vec![0; records],
                        tx: vec![0; records],
                    },
                })
            })
            .collect();
        let ss: Streams<'_, U> = Ss::new(self.listeners, &mut storage).map_err(RunError::Policy)?;
        let certs = Mutex::new(self.certs);
        let make_tls = |id: ListenerId| {
            let mut all = certs.lock().unwrap_or_else(PoisonError::into_inner);
            let c = all.get_mut(usize::try_from(id.index()).ok()?)?.as_mut()?;
            // one that cannot be made is refused, and the socket closed
            npro_aws_lc::server(c.config(std::time::Instant::now())).ok()
        };
        let listening = (0..)
            .zip(self.sockets)
            .map(|(i, s)| (ListenerId::new(i), s));
        threads::serve(
            ss,
            listening.collect(),
            make_tls,
            |ss: &mut Streams<'_, U>, now| app(ss, now),
            stop,
        );
        Ok(())
    }
}
