use std::io;
use std::path::Path;
use std::sync::Arc;

use args::Args;
use clap::Parser;
use tokio::fs;
use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use tracing::level_filters::LevelFilter;
use tracing::{info, subscriber};
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{fmt, Registry};

pub use crate::auth::Auth;
use crate::config::Config;
pub use crate::err::Error;
#[doc(hidden)]
pub use crate::server::HyperServer;

mod addr;
mod args;
mod auth;
mod config;
mod err;
mod server;
mod tls_accept;

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

    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));
    let tcp_listener = TcpListener::bind(config.listen_addr).await?;

    info!(listen_addr = %config.listen_addr, "start listen");

    let auth = Auth::new(config.token_secret, None)?;

    let mut server = HyperServer::new(&config.token_header, auth, tcp_listener, tls_acceptor);

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

fn init_log(debug: bool) {
    let layer = fmt::layer()
        .pretty()
        .with_target(true)
        .with_writer(io::stderr);

    let level = if debug {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };

    let targets = Targets::new()
        .with_target("h2", LevelFilter::OFF)
        .with_default(LevelFilter::DEBUG);

    let layered = Registry::default().with(targets).with(layer).with(level);

    subscriber::set_global_default(layered).unwrap();
}
