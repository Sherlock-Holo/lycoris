use std::net::SocketAddr;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub remote_domain: String,
    pub remote_port: Option<u16>,
    pub totp_secret: String,
    pub token_header: String,
}
