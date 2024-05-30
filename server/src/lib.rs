#![feature(type_alias_impl_trait)]

use std::path::Path;

use args::Args;
use clap::Parser;
use futures_rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use futures_rustls::rustls::ServerConfig;
use protocol::auth::Auth;
use share::log::init_log;
use tokio::fs;
use tokio::net::TcpListener;
use tracing::info;

use crate::config::Config;
pub use crate::err::Error;
#[doc(hidden)]
pub use crate::server::HyperServer;

mod args;
mod config;
mod err;
mod server;

pub async fn run() -> Result<(), Error> {
    let args = Args::parse();
    let config = fs::read(args.config).await?;
    let config = serde_yaml::from_slice::<Config>(&config)?;

    init_log(args.debug);

    info!(token_header = %config.token_header, "get token header");

    let certs = load_certs(&config.cert).await?;
    let mut keys = load_keys(&config.key).await?;
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, keys.remove(0).into())?;

    let tcp_listener = TcpListener::bind(config.listen_addr).await?;

    info!(listen_addr = %config.listen_addr, "start listen");

    let auth = Auth::new(config.token_secret, None).map_err(|err| Error::Other(err.into()))?;
    let server = HyperServer::new(config.token_header, auth, tcp_listener, server_config)?;

    server.start().await
}

async fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, Error> {
    let certs = fs::read(path).await?;

    Ok(rustls_pemfile::certs(&mut certs.as_slice()).collect::<Result<Vec<_>, _>>()?)
}

async fn load_keys(path: &Path) -> Result<Vec<PrivatePkcs8KeyDer<'static>>, Error> {
    let keys = fs::read(path).await?;

    Ok(rustls_pemfile::pkcs8_private_keys(&mut keys.as_slice()).collect::<Result<Vec<_>, _>>()?)
}
