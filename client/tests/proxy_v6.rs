use std::any::Any;
use std::ffi::OsStr;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::{env, io};

use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::Array;
use aya::programs::cgroup_sock_addr::CgroupSockAddrLink;
use aya::programs::{CgroupSockAddr, OwnedLink, SockOps};
use aya::Bpf;
use aya_log::BpfLogger;
use bytes::Bytes;
use cidr::Ipv6Inet;
use futures_util::StreamExt;
use h2::server;
use http::{HeaderMap, Response};
use lycoris_client::bpf_share::{Ipv4Addr, Ipv6Addr};
use lycoris_client::{Client, Connector, Listener, TokenGenerator};
use nix::unistd::getuid;
use share::helper::Ipv6AddrExt;
use share::map_name::*;
use tokio::fs;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::{
    Certificate, ClientConfig, OwnedTrustAnchor, PrivateKey, RootCertStore, ServerConfig,
};
use tokio_rustls::webpki::TrustAnchor;
use tokio_rustls::TlsAcceptor;
use tracing::level_filters::LevelFilter;
use tracing::{info, subscriber};
use tracing_log::LogTracer;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{fmt, Registry};

const CGROUP_PATH: &str = "/sys/fs/cgroup";
const BPF_ELF: &str = "../target/bpfel-unknown-none/release/lycoris-bpf";
const TEST_LISTEN_ADDR: &str = "127.0.0.1:23333";
const TEST_LISTEN_ADDR_V6: &str = "[::1]:23333";
const TOKEN_SECRET: &str = "test";
const TOKEN_HEADER: &str = "x-secret";
const TEST_IP_CIDR: &str = "fd00::/8";
const TEST_TARGET_ADDR: &str = "fd00::1:80";
const H2_SERVER_ADDR_V6: &str = "[::1]:0";

#[tokio::test]
async fn main() {
    if env::var_os("TESTPROXY")
        .as_deref()
        .unwrap_or_else(|| OsStr::new(""))
        != OsStr::new("6")
    {
        eprintln!("skip proxy6");

        return;
    }

    if !getuid().is_root() {
        panic!("this integration test must run with root");
    }

    init_log();

    let listen_addr = SocketAddrV4::from_str(TEST_LISTEN_ADDR).unwrap();
    let listen_addr_v6 = SocketAddrV6::from_str(TEST_LISTEN_ADDR_V6).unwrap();

    let mut bpf = Bpf::load_file(BPF_ELF).unwrap();

    init_bpf_log(&mut bpf);

    set_proxy_addr(&mut bpf, listen_addr, listen_addr_v6);
    set_proxy_ip_list_blacklist_mode(&bpf);
    load_target_ip(&mut bpf);

    let _connect6_link = load_connect6(&mut bpf, Path::new(CGROUP_PATH)).await;
    let _sockops_link = load_established_sockops(&mut bpf, Path::new(CGROUP_PATH)).await;

    let h2_server_addr = start_server().await;

    info!(%h2_server_addr, "start server");

    let listener = load_listener(&mut bpf, listen_addr, listen_addr_v6).await;
    let connector = load_connector(
        "localhost",
        h2_server_addr.port(),
        Path::new("tests/ca.cert"),
        TOKEN_SECRET,
        TOKEN_HEADER,
    )
    .await;

    tokio::spawn(async move {
        if let Err(err) = Client::new(connector, listener).start().await {
            panic!("{}", err);
        }
    });

    info!("start client");

    let mut tcp_stream = TcpStream::connect(TEST_TARGET_ADDR).await.unwrap();
    let local_addr = tcp_stream.local_addr().unwrap();
    let peer_addr = tcp_stream.peer_addr().unwrap();

    info!(%local_addr, %peer_addr, "get tcp addr done");

    let mut buf = vec![0; 4];
    let n = tcp_stream.read_exact(&mut buf).await.unwrap();

    assert_eq!(&buf[..n], b"test");
}

async fn start_server() -> SocketAddr {
    let mut keys = load_keys(Path::new("tests/server.key")).await;
    let certs = load_certs(Path::new("tests/server.cert")).await;
    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, keys.remove(0))
        .unwrap();

    let listener = TcpListener::bind(H2_SERVER_ADDR_V6).await.unwrap();
    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

    let h2_server_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (tcp_stream, _) = listener.accept().await.unwrap();

        let tls_stream = tls_acceptor.accept(tcp_stream).await.unwrap();

        let mut connection = server::handshake(tls_stream).await.unwrap();

        while let Some(result) = connection.accept().await {
            let (recv_stream, mut send_stream) = result.unwrap();

            tokio::spawn(async move {
                let mut recv_stream = recv_stream.into_body();
                let addr_data = recv_stream.next().await.unwrap().unwrap();

                info!("addr data {:?}", addr_data.as_ref());

                let mut send_stream = send_stream.send_response(Response::new(()), false).unwrap();

                send_stream
                    .send_data(Bytes::from_static(b"test"), false)
                    .unwrap();

                send_stream.send_trailers(HeaderMap::new()).unwrap();
            });
        }
    });

    h2_server_addr
}

async fn load_certs(path: &Path) -> Vec<Certificate> {
    let certs = fs::read(path).await.unwrap();
    let mut certs = rustls_pemfile::certs(&mut certs.as_slice()).unwrap();

    certs.drain(..).map(Certificate).collect()
}

async fn load_keys(path: &Path) -> Vec<PrivateKey> {
    let keys = fs::read(path).await.unwrap();
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut keys.as_slice()).unwrap();

    keys.drain(..).map(PrivateKey).collect()
}

async fn load_connector(
    remote_domain: &str,
    remote_port: u16,
    ca_cert: &Path,
    token_secret: &str,
    token_header: &str,
) -> Connector {
    let mut root_cert_store = RootCertStore::empty();

    let ca_cert = fs::read(ca_cert).await.unwrap();
    let ca_certs = rustls_pemfile::certs(&mut ca_cert.as_slice()).unwrap();

    let ca_certs = ca_certs.iter().map(|cert| {
        let ta = TrustAnchor::try_from_cert_der(cert).unwrap();

        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    });

    root_cert_store.add_server_trust_anchors(ca_certs.into_iter());

    let client_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    let token_generator = TokenGenerator::new(token_secret.to_string(), None).unwrap();

    Connector::new(
        client_config,
        remote_domain,
        remote_port,
        token_generator,
        token_header,
    )
    .await
    .unwrap()
}

async fn load_listener(
    bpf: &mut Bpf,
    listen_addr: SocketAddrV4,
    listen_addr_v6: SocketAddrV6,
) -> Listener {
    let ipv4_map = bpf
        .map_mut(IPV4_ADDR_MAP)
        .expect("IPV4_ADDR_MAP bpf lru map not found");
    let ipv6_map = bpf
        .map_mut(IPV6_ADDR_MAP)
        .expect("IPV6_ADDR_MAP bpf lru map not found");

    Listener::new(listen_addr, listen_addr_v6, ipv4_map, ipv6_map)
        .await
        .unwrap()
}

async fn load_connect6(bpf: &mut Bpf, cgroup_path: &Path) -> OwnedLink<CgroupSockAddrLink> {
    let cgroup_file = File::open(cgroup_path).await.unwrap();

    let connect6_prog: &mut CgroupSockAddr = bpf
        .program_mut("connect6")
        .expect("bpf connect6 not found")
        .try_into()
        .unwrap();

    connect6_prog.load().unwrap();

    info!("load connect6 done");

    let connect6_link_id = connect6_prog.attach(cgroup_file).unwrap();

    info!(?cgroup_path, "attach cgroup done");

    connect6_prog.take_link(connect6_link_id).unwrap()
}

// return Box<dyn Any> because the SockOpsLink is un-exported
async fn load_established_sockops(bpf: &mut Bpf, cgroup_path: &Path) -> Box<dyn Any> {
    let cgroup_file = File::open(cgroup_path).await.unwrap();

    let prog: &mut SockOps = bpf
        .program_mut("established_connect")
        .expect("bpf established_connect not found")
        .try_into()
        .unwrap();

    prog.load().unwrap();

    info!("loaded established_connect done");

    let link_id = prog.attach(cgroup_file).unwrap();

    info!("attach established_connect done");

    Box::new(prog.take_link(link_id).unwrap())
}

fn load_target_ip(bpf: &mut Bpf) {
    let proxy_ipv6_list: LpmTrie<_, [u16; 8], u8> = bpf
        .map_mut(PROXY_IPV6_LIST)
        .expect("PROXY_IPV4_LIST not found")
        .try_into()
        .unwrap();

    let ipv6_inet = Ipv6Inet::from_str(TEST_IP_CIDR).unwrap();

    proxy_ipv6_list
        .insert(
            &Key::new(
                ipv6_inet.network_length() as _,
                ipv6_inet.first_address().network_order_segments(),
            ),
            1,
            0,
        )
        .unwrap();
}

fn set_proxy_addr(bpf: &mut Bpf, addr: SocketAddrV4, addr_v6: SocketAddrV6) {
    let mut proxy_server: Array<_, Ipv4Addr> = bpf
        .map_mut(PROXY_IPV4_CLIENT)
        .expect("PROXY_IPV4_CLIENT bpf array not found")
        .try_into()
        .unwrap();

    let proxy_addr = Ipv4Addr {
        addr: addr.ip().octets(),
        port: addr.port(),
        _padding: [0; 2],
    };

    proxy_server.set(0, proxy_addr, 0).unwrap();

    let mut v6_proxy_server: Array<_, Ipv6Addr> = bpf
        .map_mut(PROXY_IPV6_CLIENT)
        .expect("PROXY_IPV6_CLIENT bpf array not found")
        .try_into()
        .unwrap();

    let proxy_addr = Ipv6Addr {
        addr: addr_v6.ip().network_order_segments(),
        port: addr.port(),
    };

    v6_proxy_server.set(0, proxy_addr, 0).unwrap();
}

fn set_proxy_ip_list_blacklist_mode(bpf: &Bpf) {
    let mut proxy_ipv4_list_mode: Array<_, u8> = bpf
        .map_mut(PROXY_IPV4_LIST_MODE)
        .expect("PROXY_IPV4_LIST_MODE not found")
        .try_into()
        .unwrap();

    proxy_ipv4_list_mode.set(0, 0u8, 0).unwrap();
}

fn init_log() {
    let layer = fmt::layer()
        .pretty()
        .with_target(true)
        .with_writer(io::stderr);
    let targets = Targets::new()
        .with_target("h2", LevelFilter::OFF)
        .with_default(LevelFilter::DEBUG);
    let layered = Registry::default()
        .with(targets)
        .with(layer)
        .with(LevelFilter::DEBUG);

    subscriber::set_global_default(layered).unwrap();
}

fn init_bpf_log(bpf: &mut Bpf) {
    LogTracer::builder().ignore_crate("rustls").init().unwrap();

    BpfLogger::init(bpf).unwrap();
}
