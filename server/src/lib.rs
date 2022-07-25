use std::io;
use std::path::Path;
use std::sync::Arc;

use args::Args;
use clap::Parser;
use tokio::fs;
use tokio::net::TcpListener;
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};
use tokio_rustls::TlsAcceptor;
use tracing::level_filters::LevelFilter;
use tracing::{info, subscriber};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{fmt, Registry};

pub use crate::auth::Auth;
use crate::config::Config;
pub use crate::err::Error;
pub use crate::server::Server;

mod args;
mod async_read_recv_stream;
mod async_write_send_stream;
mod auth;
mod config;
mod err;
mod h2_connection;
mod parse;
mod proxy;
mod server;

pub async fn run() -> Result<(), Error> {
    let args = Args::parse();
    let config = fs::read(args.config).await?;
    let config = serde_yaml::from_slice::<Config>(&config)?;

    init_log();

    info!(token_header = %config.token_header, "get token header");

    let certs = load_certs(&config.cert).await?;
    let mut keys = load_keys(&config.key).await?;
    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, keys.remove(0))?;

    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));
    let tcp_listener = TcpListener::bind(config.listen_addr).await?;

    info!(listen_addr = %config.listen_addr, "start listen");

    let auth = Auth::new(config.totp_secret, None)?;

    let mut server = Server::new(&config.token_header, auth, tcp_listener, tls_acceptor);

    server.start().await
}

async fn load_certs(path: &Path) -> Result<Vec<Certificate>, Error> {
    let certs = fs::read(path).await?;
    let mut certs =
        rustls_pemfile::certs(&mut certs.as_slice()).map_err(|err| Error::Other(err.into()))?;

    Ok(certs.drain(..).map(Certificate).collect())
}

async fn load_keys(path: &Path) -> Result<Vec<PrivateKey>, Error> {
    let keys = fs::read(path).await?;
    let mut keys = rustls_pemfile::rsa_private_keys(&mut keys.as_slice())
        .map_err(|err| Error::Other(err.into()))?;

    Ok(keys.drain(..).map(PrivateKey).collect())
}

fn init_log() {
    let layer = fmt::layer()
        .pretty()
        .with_target(true)
        .with_writer(io::stderr);
    let layered = Registry::default().with(layer).with(LevelFilter::INFO);

    subscriber::set_global_default(layered).unwrap();
}
