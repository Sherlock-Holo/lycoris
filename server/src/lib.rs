#![feature(type_alias_impl_trait)]

use std::path::Path;

use args::Args;
use clap::Parser;
use futures_rustls::pki_types::{CertificateDer, PrivateKeyDer};
use futures_rustls::rustls::ServerConfig;
use protocol::auth::Auth;
use rustls_pemfile::Item;
use share::log::init_log;
use tokio::fs;
use tokio::net::TcpListener;
use tracing::info;

use self::config::Config;
pub use self::err::Error;
#[doc(hidden)]
pub use self::mptcp::MptcpListenerExt;
#[doc(hidden)]
pub use self::server::HyperServer;

mod args;
mod config;
mod err;
mod mptcp;
mod server;

pub async fn run() -> Result<(), Error> {
    let args = Args::parse();
    let config = fs::read(args.config).await?;
    let config = serde_yaml::from_slice::<Config>(&config)?;

    init_log(args.debug);

    info!(token_header = %config.token_header, "get token header");

    let certs = load_certs(&config.cert).await?;
    let key = load_key(&config.key).await?;
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    let tcp_listener = TcpListener::listen_mptcp(config.listen_addr).await?;

    info!(listen_addr = %config.listen_addr, "start listen");

    let auth = Auth::new(config.token_secret, None).map_err(|err| Error::Other(err.into()))?;
    let server = HyperServer::new(config.token_header, auth, tcp_listener, server_config)?;

    server.start().await
}

async fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, Error> {
    let certs = fs::read(path).await?;

    Ok(rustls_pemfile::certs(&mut certs.as_slice()).collect::<Result<Vec<_>, _>>()?)
}

async fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, Error> {
    let data = fs::read(path).await?;

    let item = rustls_pemfile::read_one_from_slice(&data)?
        .ok_or_else(|| Error::Other("no key found".into()))?
        .0;

    match item {
        Item::X509Certificate(_) | Item::SubjectPublicKeyInfo(_) => {
            Err(Error::Other("certificate is not private key".into()))
        }

        Item::Crl(_) => Err(Error::Other("crl is not private key".into())),
        Item::Csr(_) => Err(Error::Other("csr is not private key".into())),

        Item::Pkcs1Key(key) => Ok(key.into()),
        Item::Pkcs8Key(key) => Ok(key.into()),
        Item::Sec1Key(key) => Ok(key.into()),

        _ => Err(Error::Other("unknown key file".into())),
    }
}
