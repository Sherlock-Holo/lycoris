use std::any::Any;
use std::env;
use std::ffi::OsStr;
use std::net::{SocketAddrV4, SocketAddrV6};
use std::path::Path;
use std::str::FromStr;

use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::Array;
use aya::programs::cgroup_sock_addr::CgroupSockAddrLink;
use aya::programs::{CgroupSockAddr, SockOps};
use aya::{Bpf, BpfLoader};
use aya_log::BpfLogger;
use cidr::Ipv6Inet;
use lycoris_client::bpf_map_name::*;
use lycoris_client::bpf_share::{Ipv4Addr, Ipv6Addr};
use lycoris_client::{BpfListener, Listener, OwnedLink};
use protocol::DomainOrSocketAddr;
use rustix::process::getuid;
use share::log::init_log;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::info;
use tracing_log::LogTracer;

const CGROUP_PATH: &str = "/sys/fs/cgroup";
const BPF_ELF: &str = "../target/bpfel-unknown-none/release/lycoris-bpf";
const TEST_LISTEN_ADDR: &str = "127.0.0.1:23333";
const TEST_LISTEN_ADDR_V6: &str = "[::1]:23333";
const TEST_IP_CIDR: &str = "fd00::/8";
const TEST_TARGET_ADDR: &str = "fd00::1:80";

#[tokio::test]
async fn main() {
    if env::var_os("TESTPROXY")
        .as_deref()
        .unwrap_or_else(|| OsStr::new(""))
        != OsStr::new("6")
    {
        eprintln!("skip proxy");

        return;
    }

    if !getuid().is_root() {
        panic!("this integration test must run with root");
    }

    init_log(true);

    let listen_addr = SocketAddrV4::from_str(TEST_LISTEN_ADDR).unwrap();
    let listen_addr_v6 = SocketAddrV6::from_str(TEST_LISTEN_ADDR_V6).unwrap();

    let mut bpf = BpfLoader::new()
        .allow_unsupported_maps()
        .load_file(BPF_ELF)
        .unwrap();

    init_bpf_log(&mut bpf);

    set_proxy_addr(&mut bpf, listen_addr, listen_addr_v6);
    set_proxy_ip_list_mode(&mut bpf);
    load_target_ip(&mut bpf);

    let _connect6_link = load_connect6(&mut bpf, Path::new(CGROUP_PATH)).await;
    let _getsockname_link = load_getsockname6(&mut bpf, Path::new(CGROUP_PATH)).await;
    let _sockops_link = load_established_sockops(&mut bpf, Path::new(CGROUP_PATH)).await;

    let mut listener = load_listener(listen_addr, listen_addr_v6).await;

    tokio::spawn(async move {
        let (mut stream, addr) = listener.accept().await.unwrap();
        stream.write_all(&addr.encode()).await.unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    let tcp_stream = TcpStream::connect(TEST_TARGET_ADDR).await.unwrap();
    let local_addr = tcp_stream.local_addr().unwrap();
    let peer_addr = tcp_stream.peer_addr().unwrap();
    let mut tcp_stream = tcp_stream.compat();

    info!(%local_addr, %peer_addr, "get tcp addr done");

    let domain_or_socket_addr = DomainOrSocketAddr::parse(&mut tcp_stream).await.unwrap();

    info!(?domain_or_socket_addr, "domain or socket addr");
}

async fn load_listener(listen_addr: SocketAddrV4, listen_addr_v6: SocketAddrV6) -> BpfListener {
    BpfListener::new(listen_addr, listen_addr_v6, None, None)
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

    connect6_prog.take_link(connect6_link_id).unwrap().into()
}

async fn load_getsockname6(bpf: &mut Bpf, cgroup_path: &Path) -> OwnedLink<CgroupSockAddrLink> {
    let cgroup_file = File::open(cgroup_path).await.unwrap();

    let prog: &mut CgroupSockAddr = bpf
        .program_mut("getsockname6")
        .expect("bpf getsockname6 not found")
        .try_into()
        .unwrap();

    prog.load().unwrap();

    info!("load getsockname6 done");

    let link_id = prog.attach(cgroup_file).unwrap();

    info!(?cgroup_path, "attach cgroup done");

    prog.take_link(link_id).unwrap().into()
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

    Box::new(OwnedLink::from(prog.take_link(link_id).unwrap()))
}

fn load_target_ip(bpf: &mut Bpf) {
    let mut proxy_ipv6_list: LpmTrie<_, [u8; 16], u8> = bpf
        .map_mut(PROXY_IPV6_LIST)
        .expect("PROXY_IPV6_LIST not found")
        .try_into()
        .unwrap();

    let ipv6_inet = Ipv6Inet::from_str(TEST_IP_CIDR).unwrap();

    proxy_ipv6_list
        .insert(
            &Key::new(
                ipv6_inet.network_length() as _,
                ipv6_inet.first_address().to_bits().to_be_bytes(),
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
        addr: addr_v6.ip().to_bits().to_be_bytes(),
        port: addr.port(),
    };

    v6_proxy_server.set(0, proxy_addr, 0).unwrap();
}

fn set_proxy_ip_list_mode(bpf: &mut Bpf) {
    let mut proxy_list_mode: Array<_, u8> = bpf
        .map_mut(PROXY_LIST_MODE)
        .expect("PROXY_LIST_MODE not found")
        .try_into()
        .unwrap();

    proxy_list_mode.set(0, 1u8, 0).unwrap();
}

fn init_bpf_log(bpf: &mut Bpf) {
    LogTracer::builder().ignore_crate("rustls").init().unwrap();

    BpfLogger::init(bpf).unwrap();
}
