use std::ffi::c_int;
use std::io;
use std::net::{IpAddr, SocketAddr, TcpListener as StdTcpListener};

use libc::SOCK_NONBLOCK;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpListener;

#[allow(async_fn_in_trait)]
pub trait MptcpListenerExt {
    async fn listen_mptcp(addr: SocketAddr) -> io::Result<Self>
    where
        Self: Sized;
}

impl MptcpListenerExt for TcpListener {
    async fn listen_mptcp(addr: SocketAddr) -> io::Result<Self>
    where
        Self: Sized,
    {
        let domain = match addr.ip() {
            IpAddr::V4(_) => Domain::IPV4,
            IpAddr::V6(_) => Domain::IPV6,
        };

        let ty = Type::from(SOCK_NONBLOCK | c_int::from(Type::STREAM));
        let socket = Socket::new(domain, ty, Some(Protocol::MPTCP))?;
        socket.set_reuse_address(true)?;
        socket.set_reuse_port(true)?;

        socket.bind(&addr.into())?;
        socket.listen(1024)?;

        let std_tcp_listener = StdTcpListener::from(socket);

        TcpListener::from_std(std_tcp_listener)
    }
}
