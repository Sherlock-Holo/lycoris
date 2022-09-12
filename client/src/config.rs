use std::net::{SocketAddrV4, SocketAddrV6};
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub listen_addr: SocketAddrV4,
    pub listen_addr_v6: SocketAddrV6,
    pub remote_domain: String,
    pub remote_port: Option<u16>,
    pub ca_cert: Option<PathBuf>,
    pub token_secret: String,
    pub token_header: String,
    pub cgroup_path: PathBuf,
    #[serde(default = "default_blacklist_mode")]
    pub blacklist_mode: bool,
    pub ip_list: Vec<PathBuf>,
}

#[inline]
const fn default_blacklist_mode() -> bool {
    true
}
