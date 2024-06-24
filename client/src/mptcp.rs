use std::ffi::c_int;
use std::io;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, TcpStream as StdTcpStream};
use std::pin::pin;
use std::time::Duration;

use futures_util::{stream, Stream, StreamExt};
use libc::{EINPROGRESS, SOCK_NONBLOCK};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::TcpStream;
use tokio::time;

use crate::stream_staggered::AsyncIteratorExt;
use crate::stream_staggered::StreamStaggered;

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
        let mut v6 = vec![];
        let mut v4 = vec![];
        let mut addrs = pin!(addrs);
        let mut last_err = None;
        while let Some(addr) = addrs.next().await {
            match addr {
                Err(err) => {
                    last_err = Some(err);
                }

                Ok(SocketAddr::V4(addr)) => {
                    v4.push(SocketAddr::V4(addr));
                }
                Ok(SocketAddr::V6(addr)) => {
                    v6.push(SocketAddr::V6(addr));
                }
            }
        }
        if let Some(err) = last_err {
            if v4.is_empty() && v6.is_empty() {
                return Err(err);
            }
        }

        let mut ip_count = v4.len() + v6.len();
        let addrs = stream::iter(v6).staggered(stream::iter(v4));
        let mut addrs = pin!(addrs);
        let mut last_addr = None;
        while let Some(addr) = addrs.next().await {
            ip_count -= 1;
            if ip_count == 0 {
                last_addr = Some(addr);
                break;
            }

            let connect_fut = time::timeout(Duration::from_millis(250), async {
                connect_mptcp_addr(addr).await
            })
            .await;

            if let Ok(Ok(stream)) = connect_fut {
                return Ok(stream);
            }
        }

        connect_mptcp_addr(last_addr.unwrap()).await
    }
}

async fn connect_mptcp_addr(mut addr: SocketAddr) -> io::Result<TcpStream> {
    let ty = Type::from(SOCK_NONBLOCK | c_int::from(Type::STREAM));
    let socket = Socket::new(Domain::IPV6, ty, Some(Protocol::MPTCP))?;

    if let IpAddr::V4(ip) = addr.ip() {
        addr.set_ip(ip.to_ipv6_mapped().into());
    }

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
