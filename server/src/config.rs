use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    key: PathBuf,
    cert: PathBuf,
    domain: Option<String>,
    listen_addr: SocketAddr,
    totp_secret: String,
}
