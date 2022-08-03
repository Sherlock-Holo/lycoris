use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub key: PathBuf,
    pub cert: PathBuf,
    pub listen_addr: SocketAddr,
    pub token_secret: String,
    pub token_header: String,
}
