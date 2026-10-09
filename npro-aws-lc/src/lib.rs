//! npro with tls by rustls, its crypto provider aws-lc-rs.
//!
//! npro-io binds rustls to its driver with no crypto provider; this crate
//! gives it aws-lc-rs, AWS-LC's crypto, whose C npro keeps out of its own
//! graph.  It makes the record layers a driver is given
//! ([`npro_io::driver::Driver::with_tls`]) from a rustls config, built
//! with [`provider`].

#![forbid(unsafe_code)]

use std::sync::Arc;

use npro_io::tls::rustls::{RustlsClient, RustlsServer};
use rustls::client::UnbufferedClientConnection;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::ServerName;
use rustls::server::UnbufferedServerConnection;
use rustls::{ClientConfig, ServerConfig};

/// aws-lc-rs as rustls' crypto provider, for building a config with
/// `ClientConfig::builder_with_provider` and its server equivalent.
#[must_use]
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// A client's record layer, connecting to `name` with `config`.
///
/// # Errors
///
/// rustls' error, if `config` cannot make a connection.
pub fn client(
    config: Arc<ClientConfig>,
    name: ServerName<'static>,
) -> Result<RustlsClient, rustls::Error> {
    UnbufferedClientConnection::new(config, name).map(RustlsClient::new)
}

/// A server's record layer, with `config`.
///
/// # Errors
///
/// rustls' error, if `config` cannot make a connection.
pub fn server(config: Arc<ServerConfig>) -> Result<RustlsServer, rustls::Error> {
    UnbufferedServerConnection::new(config).map(RustlsServer::new)
}
