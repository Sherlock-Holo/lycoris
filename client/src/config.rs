use std::net::{SocketAddrV4, SocketAddrV6};
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub listen_addr: SocketAddrV4,
    pub listen_addr_v6: SocketAddrV6,
    pub container_bridge_listen_addr: Option<SocketAddrV4>,
    pub container_bridge_listen_addr_v6: Option<SocketAddrV6>,
    pub remote_domain: String,
    pub remote_port: Option<u16>,
    pub ca_cert: Option<PathBuf>,
    pub token_secret: String,
    pub token_header: String,
    pub cgroup_path: PathBuf,
    #[serde(default = "default_ip_in_list_directly")]
    pub ip_in_list_directly: bool,
    #[serde(default)]
    pub command_list: Vec<String>,
    #[serde(default = "default_command_in_list_directly")]
    pub command_in_list_directly: bool,
    #[serde(default)]
    pub ip_list: Vec<PathBuf>,
}

impl Config {
    pub fn check(&self) -> anyhow::Result<()> {
        for command in &self.command_list {
            if command.len() > 15 {
                return Err(anyhow::anyhow!("command {command} length > 15"));
            }
        }

        Ok(())
    }
}

const fn default_command_in_list_directly() -> bool {
    true
}

const fn default_ip_in_list_directly() -> bool {
    true
}
