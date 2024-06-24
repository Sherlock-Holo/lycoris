use std::ffi::c_int;
use std::io;
use std::io::ErrorKind;
use std::net::{SocketAddr, TcpStream as StdTcpStream};
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
        let mut addrs = pin!(addrs);
        let mut last_err = None;
        while let Some(addr) = addrs.next().await {
            let addr = match addr {
                Err(err) => {
                    last_err = Some(err);

                    continue;
                }

                Ok(addr) => addr,
            };

            match connect_mptcp_addr(addr).await {
                Err(err) => {
                    last_err = Some(err);
                }

                Ok(stream) => return Ok(stream),
            }
        }

        Err(last_err.unwrap_or_else(|| io::Error::new(ErrorKind::Other, "addrs is empty")))
    }
}

async fn connect_mptcp_addr(addr: SocketAddr) -> io::Result<TcpStream> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };

    let ty = Type::from(SOCK_NONBLOCK | c_int::from(Type::STREAM));
    let socket = Socket::new(domain, ty, Some(Protocol::MPTCP))?;

    let sock_addr = SockAddr::from(addr);
    match socket.connect(&sock_addr) {
        Err(err) if err.kind() == ErrorKind::WouldBlock => {}
        Err(err) => {
            if let Some(raw_err) = err.raw_os_error() {
                if raw_err != EINPROGRESS {
                    return Err(err);
                }
            } else {
                return Err(err);
            }
        }

        Ok(_) => {}
    }

    let std_tcp_stream = StdTcpStream::from(socket);
    let tcp_stream = TcpStream::from_std(std_tcp_stream)?;
    tcp_stream.writable().await?;

    Ok(tcp_stream)
}
