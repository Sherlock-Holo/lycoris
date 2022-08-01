use std::any::Any;
use std::io;
use std::io::ErrorKind;
use std::net::{SocketAddr, SocketAddrV4};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::Array;
use aya::programs::cgroup_sock_addr::CgroupSockAddrLink;
use aya::programs::{CgroupSockAddr, OwnedLink, SockOps};
use aya::{Bpf, BpfLoader};
use aya_log::BpfLogger;
use bytes::Bytes;
use cidr::Ipv4Inet;
use client::bpf_share::Ipv4Addr;
use client::{Client, Connector, Listener, TokenGenerator};
use futures_util::StreamExt;
use h2::server;
use http::Response;
use nix::unistd::getuid;
use simplelog::{ColorChoice, ConfigBuilder, TermLogger, TerminalMode};
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
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{fmt, Registry};

const CGROUP_PATH: &str = "/sys/fs/cgroup";
const BPF_PATH_ROOT: &str = "/sys/fs/bpf";
const BPF_PATH: &str = "/sys/fs/bpf/lycoris_test";
const BPF_ELF: &str = "../target/bpfel-unknown-none/release/bpf";
const TEST_LISTEN_ADDR: &str = "127.0.0.1:23333";
const TOKEN_SECRET: &str = "test";
const TOKEN_HEADER: &str = "x-secret";
const TEST_IP_CIDR: &str = "172.20.0.0/16";
const TEST_TARGET_ADDR: &str = "172.20.0.1:80";
const H2_SERVER_ADDR: &str = "127.0.0.1:0";

#[tokio::test]
async fn main() {
    if !getuid().is_root() {
        panic!("this integration test must run with root");
    }

    if !fs::metadata(BPF_PATH_ROOT).await.unwrap().is_dir() {
        panic!("bpf path root {} is not dir", BPF_PATH_ROOT);
    }

    if let Err(err) = fs::create_dir(BPF_PATH).await {
        if err.kind() != ErrorKind::AlreadyExists {
            panic!("{}", err);
        }
    }

    init_log();

    let listen_addr = SocketAddrV4::from_str(TEST_LISTEN_ADDR).unwrap();

    let mut bpf = BpfLoader::new()
        .map_pin_path(BPF_PATH)
        .load_file(BPF_ELF)
        .unwrap();

    init_bpf_log(&mut bpf);

    set_proxy_addr(&mut bpf, listen_addr);
    load_target_ip(&mut bpf);

    let _connect4_link = load_connect4(&mut bpf, Path::new(CGROUP_PATH)).await;
    let _sockops_link = load_established_sockops(&mut bpf, Path::new(CGROUP_PATH)).await;

    let h2_server_addr = start_server().await;

    info!("start server");

    let listener = load_v4_listener(&mut bpf, listen_addr).await;
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

    info!("read data {}", String::from_utf8_lossy(&buf[..n]));
}

async fn start_server() -> SocketAddr {
    let mut keys = load_keys(Path::new("tests/server.key")).await;
    let certs = load_certs(Path::new("tests/server.cert")).await;
    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, keys.remove(0))
        .unwrap();

    let listener = TcpListener::bind(H2_SERVER_ADDR).await.unwrap();
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
    let mut keys = rustls_pemfile::rsa_private_keys(&mut keys.as_slice()).unwrap();

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

async fn load_v4_listener(bpf: &mut Bpf, listen_addr: SocketAddrV4) -> Listener {
    let map_ref_mut = bpf
        .map_mut("IPV4_ADDR_MAP")
        .expect("IPV4_ADDR_MAP bpf lru map not found");

    Listener::new(listen_addr, map_ref_mut).await.unwrap()
}

async fn load_connect4(bpf: &mut Bpf, cgroup_path: &Path) -> OwnedLink<CgroupSockAddrLink> {
    let cgroup_file = File::open(cgroup_path).await.unwrap();

    let connect4_prog: &mut CgroupSockAddr = bpf
        .program_mut("connect4")
        .expect("bpf connect4 not found")
        .try_into()
        .unwrap();

    connect4_prog.load().unwrap();

    info!("load connect4 done");

    let connect4_link_id = connect4_prog.attach(cgroup_file).unwrap();

    info!(?cgroup_path, "attach cgroup done");

    connect4_prog.take_link(connect4_link_id).unwrap()
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

    println!("loaded established_connect done");

    let link_id = prog.attach(cgroup_file).unwrap();

    println!("attach established_connect done");

    Box::new(prog.take_link(link_id).unwrap())
}

fn load_target_ip(bpf: &mut Bpf) {
    let proxy_ipv4_list: LpmTrie<_, [u8; 4], u8> = bpf
        .map_mut("PROXY_IPV4_LIST")
        .expect("PROXY_IPV4_LIST not found")
        .try_into()
        .unwrap();

    let ipv4_inet = Ipv4Inet::from_str(TEST_IP_CIDR).unwrap();

    proxy_ipv4_list
        .insert(
            &Key::new(
                ipv4_inet.network_length() as _,
                ipv4_inet.first_address().octets(),
            ),
            1,
            0,
        )
        .unwrap();
}

fn set_proxy_addr(bpf: &mut Bpf, addr: SocketAddrV4) {
    let mut proxy_server: Array<_, Ipv4Addr> = bpf
        .map_mut("PROXY_SERVER")
        .expect("PROXY_SERVER bpf array not found")
        .try_into()
        .unwrap();

    let proxy_addr = Ipv4Addr {
        addr: addr.ip().octets(),
        port: addr.port(),
        _padding: [0; 2],
    };

    proxy_server.set(0, proxy_addr, 0).unwrap();
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
    use simplelog::LevelFilter;

    TermLogger::init(
        LevelFilter::Debug,
        ConfigBuilder::new()
            .add_filter_ignore("rustls".to_string())
            .set_target_level(LevelFilter::Info)
            .set_location_level(LevelFilter::Info)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap();

    // Will log using the default logger, which is TermLogger in this case
    BpfLogger::init(bpf).unwrap();
}
