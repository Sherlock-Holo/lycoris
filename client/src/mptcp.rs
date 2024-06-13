use std::ffi::c_int;
use std::io;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, TcpStream as StdTcpStream};

use libc::{EINPROGRESS, SOCK_NONBLOCK};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::TcpStream;

pub trait MptcpExt {
    async fn connect_mptcp<I: IntoIterator<Item = SocketAddr>>(addrs: I) -> io::Result<Self>
    where
        Self: Sized;
}

impl MptcpExt for TcpStream {
    async fn connect_mptcp<I: IntoIterator<Item = SocketAddr>>(addrs: I) -> io::Result<Self>
    where
        Self: Sized,
    {
        let ty = Type::from(SOCK_NONBLOCK | c_int::from(Type::STREAM));
        let socket = Socket::new(Domain::IPV6, ty, Some(Protocol::MPTCP))?;

        let mut last_err = None;
        for mut addr in addrs {
            if let IpAddr::V4(ip) = addr.ip() {
                let ip = ip.to_ipv6_mapped();
                addr.set_ip(ip.into());
            }
            let sock_addr = SockAddr::from(addr);
            match socket.connect(&sock_addr) {
                Err(err) if err.kind() == ErrorKind::WouldBlock => {}
                Err(err) => {
                    if let Some(raw_err) = err.raw_os_error() {
                        if raw_err == EINPROGRESS {
                            continue;
                        }
                    }

                    last_err = Some(err);
                }

                Ok(_) => {
                    last_err = None;
                }
            }
        }

        if let Some(err) = last_err {
            return Err(err);
        }

        let std_tcp_stream = StdTcpStream::from(socket);
        let tcp_stream = TcpStream::from_std(std_tcp_stream)?;
        tcp_stream.writable().await?;

        Ok(tcp_stream)
    }
}
