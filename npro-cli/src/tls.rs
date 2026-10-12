//! A tls listener's certificate and key, by path, and its config made
//! again when they change on disk.
//!
//! The certificate and key are named by the policy (`policy::Tls`), as
//! lwsws names them: npro.rs' are `-latest` names its cert renewal
//! replaces.  C's `tls-cert-watch.c` watches the directories with
//! inotify, which std does not have; here the files are looked at, at
//! most every [`CHECK_EVERY`], when a connection is accepted, and if
//! either changed the config is made again for the connections after.  A
//! pair that does not load (half written, say) keeps the config there was,
//! as C keeps its old context, and is tried again at the next look.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// How often the files are looked at, at most.
pub const CHECK_EVERY: Duration = Duration::from_secs(10);

/// What a listener's connections are offered by ALPN: h1 alone, until npro
/// has h2.
const ALPN: &[u8] = b"http/1.1";

/// Why a certificate and key did not load.
#[derive(Debug)]
pub enum CertError {
    /// A file could not be read.
    Read {
        /// Which.
        path: PathBuf,
        /// Why.
        error: io::Error,
    },
    /// The certificate file has no certificate, or one that is not PEM.
    Cert(PathBuf),
    /// The key file has no private key, or one that is not PEM.
    Key(PathBuf),
    /// rustls would not take them: the key is not the certificate's, or
    /// of a kind it does not have.
    Refused(rustls::Error),
}

impl core::fmt::Display for CertError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Read { path, error } => write!(f, "{}: {error}", path.display()),
            Self::Cert(p) => write!(f, "{}: no PEM certificate", p.display()),
            Self::Key(p) => write!(f, "{}: no PEM private key", p.display()),
            Self::Refused(e) => write!(f, "refused: {e}"),
        }
    }
}

impl core::error::Error for CertError {}

/// When a file last changed, and how long it is, as far as can be seen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stamp {
    modified: Option<SystemTime>,
    len: u64,
}

fn stamp(p: &Path) -> Option<Stamp> {
    let m = fs::metadata(p).ok()?;
    Some(Stamp {
        modified: m.modified().ok(),
        len: m.len(),
    })
}

/// A listener's certificate and key, and the config made from them.
#[derive(Debug)]
pub struct Certs {
    cert: PathBuf,
    key: PathBuf,
    /// The files as they were when the config was made, or last tried.
    seen: (Option<Stamp>, Option<Stamp>),
    config: Arc<ServerConfig>,
    checked: Instant,
    /// Why the files did not load, the last time they changed.
    failed: Option<CertError>,
}

/// Makes a server config from the PEM files `cert` (the chain, leaf
/// first) and `key`.
fn load(cert: &Path, key: &Path) -> Result<Arc<ServerConfig>, CertError> {
    let read = |p: &Path| {
        fs::read(p).map_err(|error| CertError::Read {
            path: p.to_path_buf(),
            error,
        })
    };
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&read(cert)?)
        .collect::<Result<_, _>>()
        .map_err(|_| CertError::Cert(cert.to_path_buf()))?;
    if chain.is_empty() {
        return Err(CertError::Cert(cert.to_path_buf()));
    }
    let key_der = PrivateKeyDer::from_pem_slice(&read(key)?)
        .map_err(|_| CertError::Key(key.to_path_buf()))?;
    let mut config = ServerConfig::builder_with_provider(npro_aws_lc::provider())
        .with_safe_default_protocol_versions()
        .map_err(CertError::Refused)?
        .with_no_client_auth()
        .with_single_cert(chain, key_der)
        .map_err(CertError::Refused)?;
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(config))
}

impl Certs {
    /// Loads `cert` and `key`, at `now`.
    ///
    /// # Errors
    ///
    /// [`CertError`], if they do not load.
    pub fn load(cert: &Path, key: &Path, now: Instant) -> Result<Self, CertError> {
        let seen = (stamp(cert), stamp(key));
        Ok(Self {
            config: load(cert, key)?,
            cert: cert.to_path_buf(),
            key: key.to_path_buf(),
            seen,
            checked: now,
            failed: None,
        })
    }

    /// The config for a connection accepted at `now`: made again first if
    /// the files changed since they were last looked at, at most every
    /// [`CHECK_EVERY`].
    pub fn config(&mut self, now: Instant) -> Arc<ServerConfig> {
        if now.saturating_duration_since(self.checked) >= CHECK_EVERY {
            self.checked = now;
            let seen = (stamp(&self.cert), stamp(&self.key));
            if seen != self.seen {
                self.seen = seen;
                match load(&self.cert, &self.key) {
                    Ok(c) => {
                        self.config = c;
                        self.failed = None;
                    }
                    Err(e) => self.failed = Some(e),
                }
            }
        }
        Arc::clone(&self.config)
    }

    /// Why the files did not load when they last changed, the config
    /// before kept; `None` once they load.
    #[must_use]
    pub const fn failed(&self) -> Option<&CertError> {
        self.failed.as_ref()
    }
}
