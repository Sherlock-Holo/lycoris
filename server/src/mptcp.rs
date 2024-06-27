use std::ffi::c_int;
use std::io;
use std::net::{IpAddr, SocketAddr};

use libc::SOCK_NONBLOCK;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, TcpSocket};

#[allow(async_fn_in_trait)]
pub trait MptcpListenerExt {
    async fn listen_mptcp(addr: SocketAddr) -> io::Result<Self>
    where
        Self: Sized;
}

impl MptcpListenerExt for TcpListener {
    async fn listen_mptcp(mut addr: SocketAddr) -> io::Result<Self>
    where
        Self: Sized,
    {
        let ty = Type::from(SOCK_NONBLOCK | c_int::from(Type::STREAM));
        let socket = Socket::new(Domain::IPV6, ty, Some(Protocol::MPTCP))?;
        socket.set_reuse_address(true)?;
        socket.set_reuse_port(true)?;
        if let IpAddr::V4(ip) = addr.ip() {
            addr.set_ip(ip.to_ipv6_mapped().into());
        }

        let tcp_socket = TcpSocket::from_std_stream(socket.into());
        tcp_socket.bind(addr)?;
        tcp_socket.listen(1024)
    }
}
