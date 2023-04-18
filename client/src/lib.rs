use std::any::Any;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::path::Path;
use std::str::FromStr;

use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::Array;
use aya::programs::cgroup_sock_addr::CgroupSockAddrLink;
use aya::programs::{CgroupSockAddr, SockOps};
use aya::Bpf;
use aya_log::BpfLogger;
use cidr::{Ipv4Inet, Ipv6Inet};
use clap::Parser;
use futures_util::{future, StreamExt};
use share::helper::Ipv6AddrExt;
use share::map_name::*;
use tokio::fs::{self, File};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio_rustls::rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};
use tokio_stream::wrappers::LinesStream;
use tracing::level_filters::LevelFilter;
use tracing::{info, subscriber, warn};
use tracing_log::LogTracer;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{fmt, Registry};
use trust_dns_resolver::error::ResolveErrorKind;
use trust_dns_resolver::AsyncResolver;
use webpki::TrustAnchor;
use webpki_roots::TLS_SERVER_ROOTS;

use crate::args::Args;
use crate::bpf_share::{Ipv4Addr as ShareIpv4Addr, Ipv6Addr as ShareIpv6Addr};
pub use crate::client::Client;
use crate::config::Config;
use crate::connect::hyper::HyperConnector;
pub use crate::connect::Connector;
pub use crate::err::Error;
#[doc(hidden)]
pub use crate::listener::bpf::BpfListener;
use crate::listener::socks::SocksListener;
pub use crate::owned_link::OwnedLink;
pub use crate::token::TokenGenerator;

mod addr;
mod args;
pub mod bpf_share;
mod client;
mod config;
mod connect;
mod err;
mod listener;
mod owned_link;
mod token;

pub async fn run() -> Result<(), Error> {
    let args = Args::parse();

    init_log(args.debug);

    let config = fs::read(&args.config).await?;
    let config = serde_yaml::from_slice::<Config>(&config)?;

    info!(?config, "load config done");

    match &args.socks_listen {
        None => run_bpf(args, config).await,
        Some(http_listen) => run_socks(http_listen, config).await,
    }
}

async fn run_bpf(args: Args, config: Config) -> Result<(), Error> {
    let remote_domain_ips = get_remote_domain_ips(&config.remote_domain).await?;

    info!(?remote_domain_ips, "get remote domain ip done");

    let mut bpf = Bpf::load_file(args.bpf_elf.expect("bpf elf not set"))?;

    init_bpf_log(&mut bpf);

    set_proxy_addr(&bpf, config.listen_addr, config.listen_addr_v6)?;

    info!(listen_addr = %config.listen_addr, "set proxy addr done");

    set_proxy_ip_list(&bpf, config.ip_list.iter().map(|path| path.as_path())).await?;

    info!("set target ip done");

    set_proxy_ip_list_mode(&bpf, config.blacklist_mode)?;

    if !config.blacklist_mode {
        append_remote_ip_list(&bpf, &remote_domain_ips)?;
    }

    info!(
        blacklist_mode = config.blacklist_mode,
        "set proxy ip list mode done"
    );

    let _connect4_link = load_connect4(
        &mut bpf,
        config.cgroup_path.as_ref().expect("cgroup path not set"),
    )
    .await?;

    info!("load connect4 done");

    let _connect6_link = load_connect6(
        &mut bpf,
        config.cgroup_path.as_ref().expect("cgroup path not set"),
    )
    .await?;

    let _sockops_link = load_established_sockops(
        &mut bpf,
        config.cgroup_path.as_ref().expect("cgroup path not set"),
    )
    .await?;

    info!("load sockops done");

    let bpf_listener = load_listener(&mut bpf, config.listen_addr, config.listen_addr_v6).await?;

    info!("load listener done");

    let connector = load_connector(
        &config.remote_domain,
        config.remote_port.unwrap_or(443),
        config.ca_cert.as_deref(),
        &config.token_secret,
        &config.token_header,
    )
    .await?;

    info!("load connector done");

    let mut client = Client::new(connector, bpf_listener);

    client.start().await
}

async fn run_socks(http_listen: &str, config: Config) -> Result<(), Error> {
    let http_listen = http_listen
        .parse()
        .map_err(|err| Error::Other(Box::new(err)))?;

    let http_listener = SocksListener::new(http_listen).await?;

    info!("create http listener done");

    let connector = load_connector(
        &config.remote_domain,
        config.remote_port.unwrap_or(443),
        config.ca_cert.as_deref(),
        &config.token_secret,
        &config.token_header,
    )
    .await?;

    info!("load connector done");

    let mut client = Client::new(connector, http_listener);

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

    Ok(connect4_prog.take_link(connect4_link_id)?.into())
}

async fn load_connect6(
    bpf: &mut Bpf,
    cgroup_path: &Path,
) -> Result<OwnedLink<CgroupSockAddrLink>, Error> {
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

    Ok(Box::new(OwnedLink::from(prog.take_link(link_id)?)))
}

fn set_proxy_addr(
    bpf: &Bpf,
    mut addr: SocketAddrV4,
    mut addr_v6: SocketAddrV6,
) -> Result<(), Error> {
    let mut v4_proxy_server: Array<_, ShareIpv4Addr> = bpf
        .map_mut(PROXY_IPV4_CLIENT)
        .expect("PROXY_IPV4_CLIENT bpf array not found")
        .try_into()?;

    if *addr.ip() == Ipv4Addr::new(0, 0, 0, 0) {
        // when set 0.0.0.0, we need bpf use 127.0.0.1 to connect local
        addr.set_ip(Ipv4Addr::new(127, 0, 0, 1));
    }

    let proxy_addr = ShareIpv4Addr {
        addr: addr.ip().octets(),
        port: addr.port(),
        _padding: [0; 2],
    };

    v4_proxy_server.set(0, proxy_addr, 0)?;

    let mut v6_proxy_server: Array<_, ShareIpv6Addr> = bpf
        .map_mut(PROXY_IPV6_CLIENT)
        .expect("PROXY_IPV6_CLIENT bpf array not found")
        .try_into()?;

    if *addr_v6.ip() == Ipv6Addr::from([0, 0, 0, 0, 0, 0, 0, 0]) {
        // when set 0.0.0.0, we need bpf use ::1 to connect local
        addr_v6.set_ip(Ipv6Addr::from([0, 0, 0, 0, 0, 0, 0, 1]));
    }

    let proxy_addr = ShareIpv6Addr {
        addr: addr_v6.ip().network_order_segments(),
        port: addr.port(),
    };

    v6_proxy_server.set(0, proxy_addr, 0)?;

    Ok(())
}

async fn load_listener(
    bpf: &mut Bpf,
    listen_addr: SocketAddrV4,
    listen_addr_v6: SocketAddrV6,
) -> Result<BpfListener, Error> {
    let ipv4_map_ref_mut = bpf
        .map_mut(IPV4_ADDR_MAP)
        .expect("IPV4_ADDR_MAP bpf lru map not found");

    let ipv6_map_ref_mut = bpf
        .map_mut(IPV6_ADDR_MAP)
        .expect("IPV6_ADDR_MAP bpf lru map not found");

    BpfListener::new(
        listen_addr,
        listen_addr_v6,
        ipv4_map_ref_mut,
        ipv6_map_ref_mut,
    )
    .await
}

async fn load_connector(
    remote_domain: &str,
    remote_port: u16,
    ca_cert: Option<&Path>,
    token_secret: &str,
    token_header: &str,
) -> Result<HyperConnector, Error> {
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

    HyperConnector::new(
        client_config,
        remote_domain,
        remote_port,
        token_generator,
        token_header,
    )
}

async fn set_proxy_ip_list<'a, I: Iterator<Item = &'a Path>>(
    bpf: &Bpf,
    ip_list_paths: I,
) -> Result<(), Error> {
    let proxy_ipv4_list: LpmTrie<_, [u8; 4], u8> = bpf
        .map_mut(PROXY_IPV4_LIST)
        .expect("PROXY_IPV4_LIST not found")
        .try_into()?;

    let proxy_ipv6_list: LpmTrie<_, [u16; 8], u8> = bpf
        .map_mut(PROXY_IPV6_LIST)
        .expect("PROXY_IPV6_LIST not found")
        .try_into()?;

    for ip_list_path in ip_list_paths {
        let ip_list = File::open(ip_list_path).await?;
        let mut reader = LinesStream::new(BufReader::new(ip_list).lines());

        while let Some(result) = reader.next().await {
            let line = result?;
            let line = line.trim();
            if line.is_empty() {
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
                        proxy_ipv6_list.insert(
                            &Key::new(
                                ipv6_net.network_length() as _,
                                ipv6_net.first_address().network_order_segments(),
                            ),
                            1,
                            0,
                        )?;
                    }
                },

                Ok(ipv4_inet) => {
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
    if let Ok(ip_addr) = IpAddr::from_str(domain) {
        return Ok(vec![ip_addr]);
    }

    let async_resolver = AsyncResolver::tokio_from_system_conf()?;

    let ipv4_fut = async {
        match async_resolver.ipv4_lookup(domain).await {
            Err(err) if matches!(err.kind(), &ResolveErrorKind::NoRecordsFound { .. }) => Ok(None),

            Err(err) => Err(Error::from(err)),

            Ok(ipv4lookup) => Ok(Some(ipv4lookup)),
        }
    };

    let ipv6_fut = async {
        match async_resolver.ipv6_lookup(domain).await {
            Err(err) if matches!(err.kind(), &ResolveErrorKind::NoRecordsFound { .. }) => Ok(None),

            Err(err) => Err(Error::from(err)),

            Ok(ipv6lookup) => Ok(Some(ipv6lookup)),
        }
    };

    let (ipv4_lookup, ipv6_lookup) = future::try_join(ipv4_fut, ipv6_fut).await?;

    Ok(ipv4_lookup
        .into_iter()
        .flatten()
        .map(IpAddr::from)
        .chain(ipv6_lookup.into_iter().flatten().map(IpAddr::from))
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
