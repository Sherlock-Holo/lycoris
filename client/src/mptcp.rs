use std::ffi::c_int;
use std::io;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, TcpStream as StdTcpStream};
use std::pin::pin;

use futures_util::{Stream, StreamExt};
use libc::{EINPROGRESS, SOCK_NONBLOCK};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::TcpStream;

pub trait MptcpExt {
    async fn connect_mptcp<S: Stream<Item = io::Result<SocketAddr>>>(addrs: S) -> io::Result<Self>
    where
        Self: Sized;
}

impl MptcpExt for TcpStream {
    async fn connect_mptcp<S: Stream<Item = io::Result<SocketAddr>>>(addrs: S) -> io::Result<Self>
    where
        Self: Sized,
    {
        let ty = Type::from(SOCK_NONBLOCK | c_int::from(Type::STREAM));
        let socket = Socket::new(Domain::IPV6, ty, Some(Protocol::MPTCP))?;

        let mut addrs = pin!(addrs);
        let mut connect_success = false;
        let mut last_err = None;
        while let Some(addr) = addrs.next().await {
            let mut addr = match addr {
                Err(err) => {
                    last_err = Some(err);

                    continue;
                }

                Ok(addr) => addr,
            };

            if let IpAddr::V4(ip) = addr.ip() {
                let ip = ip.to_ipv6_mapped();
                addr.set_ip(ip.into());
            }
            let sock_addr = SockAddr::from(addr);
            match socket.connect(&sock_addr) {
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    connect_success = true;
                }
                Err(err) => {
                    if let Some(raw_err) = err.raw_os_error() {
                        if raw_err == EINPROGRESS {
                            connect_success = true;

                            continue;
                        }
                    }

                    last_err = Some(err);
                }

                Ok(_) => {
                    connect_success = true;
                    last_err = None;
                }
            }
        }

        if let Some(err) = last_err {
            // ignore error when connect is success
            if !connect_success {
                return Err(err);
            }
        }

        let std_tcp_stream = StdTcpStream::from(socket);
        let tcp_stream = TcpStream::from_std(std_tcp_stream)?;
        tcp_stream.writable().await?;

        Ok(tcp_stream)
    }
}
