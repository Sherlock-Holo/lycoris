use std::any::Any;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::str::FromStr;

use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::Array;
use aya::programs::cgroup_sock_addr::CgroupSockAddrLink;
use aya::programs::{CgroupSockAddr, OwnedLink, SockOps};
use aya::Bpf;
use aya_log::BpfLogger;
use cidr::Ipv4Inet;
use clap::Parser;
use futures_util::io::BufReader;
use futures_util::{AsyncBufReadExt, StreamExt};
use share::map_name::*;
use tokio::fs;
use tokio::fs::File;
use tokio_rustls::rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};
use tokio_rustls::webpki::TrustAnchor;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::level_filters::LevelFilter;
use tracing::{info, subscriber};
use tracing_log::LogTracer;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{fmt, Registry};
use trust_dns_resolver::AsyncResolver;
use webpki_roots::TLS_SERVER_ROOTS;

use crate::args::Args;
use crate::bpf_share::Ipv4Addr;
pub use crate::client::Client;
use crate::config::Config;
pub use crate::connect::Connector;
pub use crate::err::Error;
pub use crate::listener::Listener;
pub use crate::token::TokenGenerator;

mod addr;
mod args;
pub mod bpf_share;
mod client;
mod config;
mod connect;
mod err;
mod listener;
mod token;

pub async fn run() -> Result<(), Error> {
    let args = Args::parse();

    init_log(args.debug);

    let config = fs::read(args.config).await?;
    let config = serde_yaml::from_slice::<Config>(&config)?;

    info!(?config, "load config done");

    let remote_domain_ips = get_remote_domain_ips(&config.remote_domain).await?;

    info!(?remote_domain_ips, "get remote domain ip done");

    let mut bpf = Bpf::load_file(args.bpf_elf)?;

    init_bpf_log(&mut bpf);

    set_proxy_addr(&bpf, config.listen_addr)?;

    info!(listen_addr = %config.listen_addr, "set proxy addr done");

    set_proxy_ip_list(&bpf, &args.ip_list).await?;

    info!("set target ip done");

    set_proxy_ip_list_mode(&bpf, config.blacklist_mode)?;

    if !config.blacklist_mode {
        append_remote_ip_list(&bpf, &remote_domain_ips)?;
    }

    info!(
        blacklist_mode = config.blacklist_mode,
        "set proxy ip list mode done"
    );

    let _connect4_link = load_connect4(&mut bpf, &config.cgroup_path).await?;

    info!("load connect4 done");

    let _sockops_link = load_established_sockops(&mut bpf, &config.cgroup_path).await?;

    info!("load sockops done");

    let v4_listener = load_v4_listener(&mut bpf, config.listen_addr).await?;

    info!("load v4 listener done");

    let connector = load_connector(
        &config.remote_domain,
        config.remote_port.unwrap_or(443),
        config.ca_cert.as_deref(),
        &config.token_secret,
        &config.token_header,
    )
    .await?;

    info!("load connector done");

    let mut client = Client::new(connector, v4_listener);

    client.start().await
}

async fn load_connect4(
    bpf: &mut Bpf,
    cgroup_path: &Path,
) -> Result<OwnedLink<CgroupSockAddrLink>, Error> {
    let cgroup_file = File::open(cgroup_path).await?;

    let connect4_prog: &mut CgroupSockAddr = bpf
        .program_mut("connect4")
        .expect("bpf connect4 not found")
        .try_into()?;

    connect4_prog.load()?;

    info!("load connect4 done");

    let connect4_link_id = connect4_prog.attach(cgroup_file)?;

    info!(?cgroup_path, "attach cgroup done");

    Ok(connect4_prog.take_link(connect4_link_id)?)
}

// return Box<dyn Any> because the SockOpsLink is un-exported
async fn load_established_sockops(
    bpf: &mut Bpf,
    cgroup_path: &Path,
) -> Result<Box<dyn Any>, Error> {
    let cgroup_file = File::open(cgroup_path).await?;

    let prog: &mut SockOps = bpf
        .program_mut("established_connect")
        .expect("bpf established_connect not found")
        .try_into()?;

    prog.load()?;

    info!("loaded established_connect done");

    let link_id = prog.attach(cgroup_file).unwrap();

    info!("attach established_connect done");

    Ok(Box::new(prog.take_link(link_id)?))
}

fn set_proxy_addr(bpf: &Bpf, addr: SocketAddr) -> Result<(), Error> {
    let addr = match addr {
        SocketAddr::V6(_) => {
            return Err(Error::Other("ipv6 is unsupported yet".into()));
        }

        SocketAddr::V4(addr) => addr,
    };

    let mut proxy_server: Array<_, Ipv4Addr> = bpf
        .map_mut(PROXY_IPV4_CLIENT)
        .expect("PROXY_IPV4_CLIENT bpf array not found")
        .try_into()?;

    let proxy_addr = Ipv4Addr {
        addr: addr.ip().octets(),
        port: addr.port(),
        _padding: [0; 2],
    };

    proxy_server.set(0, proxy_addr, 0)?;

    Ok(())
}

async fn load_v4_listener(bpf: &mut Bpf, listen_addr: SocketAddr) -> Result<Listener, Error> {
    let map_ref_mut = bpf
        .map_mut(IPV4_ADDR_MAP)
        .expect("IPV4_ADDR_MAP bpf lru map not found");

    let listen_addr = match listen_addr {
        SocketAddr::V6(_) => unreachable!(),
        SocketAddr::V4(listen_addr) => listen_addr,
    };

    Listener::new(listen_addr, map_ref_mut).await
}

async fn load_connector(
    remote_domain: &str,
    remote_port: u16,
    ca_cert: Option<&Path>,
    token_secret: &str,
    token_header: &str,
) -> Result<Connector, Error> {
    let mut root_cert_store = RootCertStore::empty();
    root_cert_store.add_server_trust_anchors(TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    if let Some(ca_cert) = ca_cert {
        let ca_cert = fs::read(ca_cert).await?;
        let ca_certs = rustls_pemfile::certs(&mut ca_cert.as_slice())?;

        let ca_certs = ca_certs
            .iter()
            .map(|cert| {
                let ta =
                    TrustAnchor::try_from_cert_der(cert).map_err(|err| Error::Other(err.into()))?;

                Ok::<_, Error>(OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;

        root_cert_store.add_server_trust_anchors(ca_certs.into_iter());
    }

    let client_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    let token_generator = TokenGenerator::new(token_secret.to_string(), None)?;

    Connector::new(
        client_config,
        remote_domain,
        remote_port,
        token_generator,
        token_header,
    )
    .await
}

async fn set_proxy_ip_list(bpf: &Bpf, ip_list: &Path) -> Result<(), Error> {
    let proxy_ipv4_list: LpmTrie<_, [u8; 4], u8> = bpf
        .map_mut(PROXY_IPV4_LIST)
        .expect("PROXY_IPV4_LIST not found")
        .try_into()?;
    let ip_list = File::open(ip_list).await?;
    let mut reader = BufReader::new(ip_list.compat()).lines();

    while let Some(result) = reader.next().await {
        let line = result?;

        let ipv4_inet = Ipv4Inet::from_str(&line).map_err(|err| Error::Other(err.into()))?;

        proxy_ipv4_list.insert(
            &Key::new(
                ipv4_inet.network_length() as _,
                ipv4_inet.first_address().octets(),
            ),
            1,
            0,
        )?;
    }

    Ok(())
}

fn append_remote_ip_list(bpf: &Bpf, remote_domain_ip: &[IpAddr]) -> Result<(), Error> {
    let proxy_ipv4_list: LpmTrie<_, [u8; 4], u8> = bpf
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

fn set_proxy_ip_list_mode(bpf: &Bpf, blacklist_mode: bool) -> Result<(), Error> {
    let mut proxy_ipv4_list_mode: Array<_, u8> = bpf
        .map_mut(PROXY_IPV4_LIST_MODE)
        .expect("PROXY_IPV4_LIST_MODE not found")
        .try_into()?;

    let mode = if blacklist_mode { 0 } else { 1 };

    proxy_ipv4_list_mode.set(0, mode, 0)?;

    Ok(())
}

async fn get_remote_domain_ips(domain: &str) -> Result<Vec<IpAddr>, Error> {
    let async_resolver = AsyncResolver::tokio_from_system_conf()?;

    Ok(async_resolver
        .lookup_ip(domain)
        .await?
        .into_iter()
        .collect())
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

fn init_bpf_log(bpf: &mut Bpf) {
    LogTracer::builder().ignore_crate("rustls").init().unwrap();

    BpfLogger::init(bpf).unwrap();
}
