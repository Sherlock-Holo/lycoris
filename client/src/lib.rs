#![feature(impl_trait_in_assoc_type, gen_blocks, async_iterator, async_closure)]

use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::path::Path;
use std::str::FromStr;

use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::Array;
use aya::programs::cgroup_sock_addr::CgroupSockAddrLink;
use aya::programs::{CgroupSockAddr, Link, SockOps};
use aya::{maps, Bpf, BpfLoader};
use aya_log::BpfLogger;
use cidr::{Ipv4Inet, Ipv6Inet};
use clap::Parser;
use futures_rustls::rustls::{ClientConfig, RootCertStore};
use futures_util::{future, StreamExt};
use hickory_resolver::error::ResolveErrorKind;
use hickory_resolver::AsyncResolver;
use protocol::auth::Auth;
use share::log::init_log;
use tokio::fs::{self, File};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio_stream::wrappers::LinesStream;
use tracing::{info, warn};
use tracing_log::LogTracer;

use self::bpf_map_name::*;
use crate::args::Args;
use crate::bpf_share::{Ipv4Addr as ShareIpv4Addr, Ipv6Addr as ShareIpv6Addr};
pub use crate::client::Client;
use crate::config::Config;
#[doc(hidden)]
pub use crate::connect::hyper::HyperConnector;
#[doc(hidden)]
pub use crate::listener::bpf::BpfListener;
#[doc(hidden)]
pub use crate::listener::Listener;
pub use crate::owned_link::OwnedLink;

mod args;
mod async_iter_ext;
pub mod bpf_map_name;
pub mod bpf_share;
mod client;
mod config;
mod connect;
mod listener;
mod mptcp;
mod owned_link;
mod stream_staggered;

pub async fn run() -> anyhow::Result<()> {
    let args = Args::parse();

    init_log(args.debug);

    let config = fs::read(&args.config).await?;
    let config = serde_yaml::from_slice::<Config>(&config)?;
    config.check()?;

    info!(?config, "load config done");

    run_bpf(args, config).await
}

async fn run_bpf(args: Args, config: Config) -> anyhow::Result<()> {
    let remote_domain_ips = get_remote_domain_ips(&config.remote_domain).await?;

    info!(?remote_domain_ips, "get remote domain ip done");

    let mut bpf = BpfLoader::new()
        // allow bpf elf contains sk_storage bpf map
        .allow_unsupported_maps()
        .load_file(&args.bpf_elf)?;

    info!("load bpf done");

    init_bpf_log(&mut bpf);

    set_proxy_addr(
        &mut bpf,
        config.listen_addr,
        config.listen_addr_v6,
        config.container_bridge_listen_addr,
        config.container_bridge_listen_addr_v6,
    )?;

    info!(listen_addr = %config.listen_addr, "set proxy addr done");

    set_proxy_ip_list(&mut bpf, config.ip_list.iter().map(|path| path.as_path())).await?;

    info!("set target ip done");

    set_proxy_ip_list_mode(&mut bpf, config.ip_in_list_directly)?;
    set_command_list(
        &mut bpf,
        config.command_list,
        config.command_in_list_directly,
    )?;

    if config.ip_in_list_directly {
        append_remote_ip_list(&mut bpf, &remote_domain_ips)?;
    }

    info!(
        ip_in_list_directly = config.ip_in_list_directly,
        "set proxy ip list mode done"
    );

    let _connect4_link = load_connect4(&mut bpf, &config.cgroup_path).await?;

    info!("load connect4 done");

    let _connect6_link = load_connect6(&mut bpf, &config.cgroup_path).await?;

    let _getsockname4 = load_getsockname4(&mut bpf, &config.cgroup_path).await?;
    let _getsockname6 = load_getsockname6(&mut bpf, &config.cgroup_path).await?;

    let _getpeername4 = load_getpeername4(&mut bpf, &config.cgroup_path).await?;
    let _getpeername6 = load_getpeername6(&mut bpf, &config.cgroup_path).await?;

    let _sockops_link = load_sockops(&mut bpf, &config.cgroup_path).await?;

    info!("load sockops done");

    let bpf_listener = load_listener(
        config.listen_addr,
        config.listen_addr_v6,
        config.container_bridge_listen_addr,
        config.container_bridge_listen_addr_v6,
    )
    .await?;

    info!("load listener done");

    let connector = load_connector(
        config.remote_domain,
        config.remote_port.unwrap_or(443),
        config.ca_cert.as_deref(),
        config.token_secret,
        config.token_header,
    )
    .await?;

    info!("load connector done");

    let mut client = Client::new(connector, bpf_listener);

    client.start().await
}

async fn load_connect4(
    bpf: &mut Bpf,
    cgroup_path: &Path,
) -> anyhow::Result<OwnedLink<CgroupSockAddrLink>> {
    let cgroup_file = File::open(cgroup_path).await?;

    let connect4_prog: &mut CgroupSockAddr = bpf
        .program_mut("connect4")
        .expect("bpf connect4 not found")
        .try_into()?;

    connect4_prog.load()?;

    info!("load connect4 done");

    let connect4_link_id = connect4_prog.attach(cgroup_file)?;

    info!(?cgroup_path, "attach cgroup done");

    Ok(connect4_prog.take_link(connect4_link_id)?.into())
}

async fn load_connect6(
    bpf: &mut Bpf,
    cgroup_path: &Path,
) -> anyhow::Result<OwnedLink<CgroupSockAddrLink>> {
    let cgroup_file = File::open(cgroup_path).await?;

    let connect6_prog: &mut CgroupSockAddr = bpf
        .program_mut("connect6")
        .expect("bpf connect6 not found")
        .try_into()?;

    connect6_prog.load()?;

    info!("load connect6 done");

    let connect6_link_id = connect6_prog.attach(cgroup_file)?;

    info!(?cgroup_path, "attach cgroup done");

    Ok(connect6_prog.take_link(connect6_link_id)?.into())
}

async fn load_getsockname4(
    bpf: &mut Bpf,
    cgroup_path: &Path,
) -> anyhow::Result<OwnedLink<CgroupSockAddrLink>> {
    let cgroup_file = File::open(cgroup_path).await?;

    let prog: &mut CgroupSockAddr = bpf
        .program_mut("getsockname4")
        .expect("bpf getsockname4 not found")
        .try_into()?;

    prog.load()?;

    info!("load getsockname4 done");

    let link_id = prog.attach(cgroup_file)?;

    info!(?cgroup_path, "attach cgroup done");

    Ok(prog.take_link(link_id)?.into())
}

async fn load_getsockname6(
    bpf: &mut Bpf,
    cgroup_path: &Path,
) -> anyhow::Result<OwnedLink<CgroupSockAddrLink>> {
    let cgroup_file = File::open(cgroup_path).await?;

    let prog: &mut CgroupSockAddr = bpf
        .program_mut("getsockname6")
        .expect("bpf getsockname4 not found")
        .try_into()?;

    prog.load()?;

    info!("load getsockname6 done");

    let link_id = prog.attach(cgroup_file)?;

    info!(?cgroup_path, "attach cgroup done");

    Ok(prog.take_link(link_id)?.into())
}

async fn load_getpeername4(
    bpf: &mut Bpf,
    cgroup_path: &Path,
) -> anyhow::Result<OwnedLink<CgroupSockAddrLink>> {
    let cgroup_file = File::open(cgroup_path).await?;

    let prog: &mut CgroupSockAddr = bpf
        .program_mut("getpeername4")
        .expect("bpf getpeername4 not found")
        .try_into()?;

    prog.load()?;

    info!("load getpeername4 done");

    let link_id = prog.attach(cgroup_file)?;

    info!(?cgroup_path, "attach cgroup done");

    Ok(prog.take_link(link_id)?.into())
}

async fn load_getpeername6(
    bpf: &mut Bpf,
    cgroup_path: &Path,
) -> anyhow::Result<OwnedLink<CgroupSockAddrLink>> {
    let cgroup_file = File::open(cgroup_path).await?;

    let prog: &mut CgroupSockAddr = bpf
        .program_mut("getpeername6")
        .expect("bpf getpeername6 not found")
        .try_into()?;

    prog.load()?;

    info!("load getpeername6 done");

    let link_id = prog.attach(cgroup_file)?;

    info!(?cgroup_path, "attach cgroup done");

    Ok(prog.take_link(link_id)?.into())
}

// return OwnedLink<impl Link> because the SockOpsLink is un-exported
async fn load_sockops(bpf: &mut Bpf, cgroup_path: &Path) -> anyhow::Result<OwnedLink<impl Link>> {
    let cgroup_file = File::open(cgroup_path).await?;

    let prog: &mut SockOps = bpf
        .program_mut("established_connect")
        .expect("bpf established_connect not found")
        .try_into()?;

    prog.load()?;

    info!("loaded established_connect done");

    let link_id = prog.attach(cgroup_file).unwrap();

    info!("attach established_connect done");

    Ok(OwnedLink::from(prog.take_link(link_id)?))
}

fn set_proxy_addr(
    bpf: &mut Bpf,
    mut addr: SocketAddrV4,
    mut addr_v6: SocketAddrV6,
    container_bridge_listen_addr: Option<SocketAddrV4>,
    container_bridge_listen_addr_v6: Option<SocketAddrV6>,
) -> anyhow::Result<()> {
    let mut v4_proxy_server: Array<_, ShareIpv4Addr> = bpf
        .map_mut(PROXY_IPV4_CLIENT)
        .expect("PROXY_IPV4_CLIENT bpf array not found")
        .try_into()?;

    if *addr.ip() == Ipv4Addr::new(0, 0, 0, 0) {
        // when set 0.0.0.0, we need bpf use 127.0.0.1 to connect local
        addr.set_ip(Ipv4Addr::LOCALHOST);
    }

    let proxy_addr = ShareIpv4Addr {
        addr: addr.ip().octets(),
        port: addr.port(),
        _padding: [0; 2],
    };

    v4_proxy_server.set(0, proxy_addr, 0)?;

    if let Some(addr) = container_bridge_listen_addr {
        let proxy_addr = ShareIpv4Addr {
            addr: addr.ip().octets(),
            port: addr.port(),
            _padding: [0; 2],
        };

        v4_proxy_server.set(1, proxy_addr, 0)?;
    }

    let mut v6_proxy_server: Array<_, ShareIpv6Addr> = bpf
        .map_mut(PROXY_IPV6_CLIENT)
        .expect("PROXY_IPV6_CLIENT bpf array not found")
        .try_into()?;

    if *addr_v6.ip() == Ipv6Addr::from([0, 0, 0, 0, 0, 0, 0, 0]) {
        // when set 0.0.0.0, we need bpf use ::1 to connect local
        addr_v6.set_ip(Ipv6Addr::LOCALHOST);
    }

    let proxy_addr = ShareIpv6Addr {
        addr: addr_v6.ip().to_bits().to_be_bytes(),
        port: addr_v6.port(),
    };

    v6_proxy_server.set(0, proxy_addr, 0)?;

    if let Some(addr_v6) = container_bridge_listen_addr_v6 {
        let proxy_addr = ShareIpv6Addr {
            addr: addr_v6.ip().to_bits().to_be_bytes(),
            port: addr_v6.port(),
        };

        v6_proxy_server.set(0, proxy_addr, 0)?;
    }

    Ok(())
}

async fn load_listener(
    listen_addr: SocketAddrV4,
    listen_addr_v6: SocketAddrV6,
    container_bridge_listen_addr: Option<SocketAddrV4>,
    container_bridge_listen_addr_v6: Option<SocketAddrV6>,
) -> anyhow::Result<BpfListener> {
    BpfListener::new(
        listen_addr,
        listen_addr_v6,
        container_bridge_listen_addr,
        container_bridge_listen_addr_v6,
    )
    .await
}

async fn load_connector(
    remote_domain: String,
    remote_port: u16,
    ca_cert: Option<&Path>,
    token_secret: String,
    token_header: String,
) -> anyhow::Result<HyperConnector> {
    let mut root_cert_store = RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs()? {
        root_cert_store.add(cert)?;
    }

    if let Some(ca_cert) = ca_cert {
        let ca_cert = fs::read(ca_cert).await?;

        for cert in rustls_pemfile::certs(&mut ca_cert.as_slice()) {
            let cert = cert?;
            root_cert_store.add(cert)?;
        }
    }

    let client_config = ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    let auth = Auth::new(token_secret, None)?;

    HyperConnector::new(
        client_config,
        remote_domain,
        remote_port,
        token_header,
        auth,
    )
}

async fn set_proxy_ip_list<'a, I: Iterator<Item = &'a Path>>(
    bpf: &mut Bpf,
    ip_list_paths: I,
) -> anyhow::Result<()> {
    for ip_list_path in ip_list_paths {
        let ip_list = File::open(ip_list_path).await?;
        let mut reader = LinesStream::new(BufReader::new(ip_list).lines());

        while let Some(result) = reader.next().await {
            let line = result?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            match Ipv4Inet::from_str(line) {
                Err(v4_err) => match Ipv6Inet::from_str(line) {
                    Err(v6_err) => {
                        warn!(
                            %v4_err,
                            %v6_err,
                            ip_cidr = %line,
                            "ip cidr is not ipv4 cidr or ipv6 cidr, ignore"
                        );

                        continue;
                    }

                    Ok(ipv6_net) => {
                        let mut proxy_ipv6_list: LpmTrie<_, [u8; 16], u8> = bpf
                            .map_mut(PROXY_IPV6_LIST)
                            .expect("PROXY_IPV6_LIST not found")
                            .try_into()?;

                        proxy_ipv6_list.insert(
                            &Key::new(
                                ipv6_net.network_length() as _,
                                ipv6_net.first_address().to_bits().to_be_bytes(),
                            ),
                            1,
                            0,
                        )?;
                    }
                },

                Ok(ipv4_inet) => {
                    let mut proxy_ipv4_list: LpmTrie<_, [u8; 4], u8> = bpf
                        .map_mut(PROXY_IPV4_LIST)
                        .expect("PROXY_IPV4_LIST not found")
                        .try_into()?;

                    proxy_ipv4_list.insert(
                        &Key::new(
                            ipv4_inet.network_length() as _,
                            ipv4_inet.first_address().octets(),
                        ),
                        1,
                        0,
                    )?;
                }
            }
        }
    }

    Ok(())
}

fn append_remote_ip_list(bpf: &mut Bpf, remote_domain_ip: &[IpAddr]) -> anyhow::Result<()> {
    let mut proxy_ipv4_list: LpmTrie<_, [u8; 4], u8> = bpf
        .map_mut(PROXY_IPV4_LIST)
        .expect("PROXY_IPV4_LIST not found")
        .try_into()?;

    for ipv4_addr in remote_domain_ip.iter().filter_map(|addr| {
        if let IpAddr::V4(addr) = addr {
            Some(addr)
        } else {
            None
        }
    }) {
        proxy_ipv4_list.insert(&Key::new(32, ipv4_addr.octets()), 1, 0)?;
    }

    Ok(())
}

fn set_proxy_ip_list_mode(bpf: &mut Bpf, ip_in_list_directly: bool) -> anyhow::Result<()> {
    let mut proxy_list_mode: Array<_, u8> = bpf
        .map_mut(PROXY_LIST_MODE)
        .expect("PROXY_LIST_MODE not found")
        .try_into()?;

    let mode = if ip_in_list_directly { 0 } else { 1 };

    proxy_list_mode.set(0, mode, 0)?;

    Ok(())
}

fn set_command_list(
    bpf: &mut Bpf,
    commands: Vec<String>,
    command_in_list_directly: bool,
) -> anyhow::Result<()> {
    let mut command_map: maps::HashMap<_, [u8; 16], u8> = bpf
        .map_mut(COMM_MAP)
        .expect("COMM_MAP not found")
        .try_into()?;

    for command in commands {
        let command = CString::new(command)?;
        let command = command.as_bytes_with_nul();
        let mut buf = [0u8; 16];
        let n = buf.len().min(command.len());
        buf[..n].copy_from_slice(&command[..n]);

        command_map.insert(buf, 1, 0)?;
    }

    let mut command_mode: Array<_, u8> = bpf
        .map_mut(COMM_MAP_MODE)
        .expect("COMM_MAP_MODE not found")
        .try_into()?;

    let command_in_list_directly = if command_in_list_directly { 0 } else { 1 };

    command_mode.set(0, command_in_list_directly, 0)?;

    Ok(())
}

async fn get_remote_domain_ips(domain: &str) -> anyhow::Result<Vec<IpAddr>> {
    if let Ok(ip_addr) = IpAddr::from_str(domain) {
        return Ok(vec![ip_addr]);
    }

    let async_resolver = AsyncResolver::tokio_from_system_conf()?;

    let ipv4_fut = async {
        match async_resolver.ipv4_lookup(domain).await {
            Err(err) if matches!(err.kind(), &ResolveErrorKind::NoRecordsFound { .. }) => Ok(None),

            Err(err) => Err(anyhow::Error::from(err)),

            Ok(ipv4lookup) => Ok(Some(ipv4lookup)),
        }
    };

    let ipv6_fut = async {
        match async_resolver.ipv6_lookup(domain).await {
            Err(err) if matches!(err.kind(), &ResolveErrorKind::NoRecordsFound { .. }) => Ok(None),

            Err(err) => Err(err.into()),

            Ok(ipv6lookup) => Ok(Some(ipv6lookup)),
        }
    };

    let (ipv4_lookup, ipv6_lookup) = future::try_join(ipv4_fut, ipv6_fut).await?;

    Ok(ipv4_lookup
        .into_iter()
        .flatten()
        .map(|record| IpAddr::from(record.0))
        .chain(
            ipv6_lookup
                .into_iter()
                .flatten()
                .map(|record| IpAddr::from(record.0)),
        )
        .collect())
}

fn init_bpf_log(bpf: &mut Bpf) {
    LogTracer::builder().ignore_crate("rustls").init().unwrap();

    BpfLogger::init(bpf).unwrap();
}
