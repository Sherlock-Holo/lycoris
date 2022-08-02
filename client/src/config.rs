use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub remote_domain: String,
    pub remote_port: Option<u16>,
    pub ca_cert: Option<PathBuf>,
    pub totp_secret: String,
    pub token_header: String,
    pub cgroup_path: PathBuf,
    pub bpf_pin_path: PathBuf,
}
