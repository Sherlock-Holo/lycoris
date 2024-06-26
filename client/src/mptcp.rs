use std::collections::VecDeque;
use std::ffi::c_int;
use std::io;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, TcpStream as StdTcpStream};
use std::pin::pin;
use std::time::Duration;

use futures_util::stream::FuturesUnordered;
use futures_util::{Stream, StreamExt};
use libc::{EINPROGRESS, SOCK_NONBLOCK};
use share::async_iter_ext::AsyncIteratorExt;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::TcpStream;
use tokio::time;
use tracing::{debug, error, instrument, warn};

pub trait MptcpExt {
    async fn connect_mptcp<S: Stream<Item = io::Result<SocketAddr>>>(addrs: S) -> io::Result<Self>
    where
        Self: Sized;
}

impl MptcpExt for TcpStream {
    #[instrument(level = "debug", skip(addrs), err)]
    async fn connect_mptcp<S: Stream<Item = io::Result<SocketAddr>>>(addrs: S) -> io::Result<Self>
    where
        Self: Sized,
    {
        let mut addrs = pin!(reorder_addrs(addrs).enumerate());
        let mut futs = FuturesUnordered::new();
        while let Some((i, addr)) = addrs.next().await {
            let addr = match addr {
                Err(err) => {
                    warn!(%err, "resolve addr failed");

                    continue;
                }

                Ok(addr) => addr,
            };

            futs.push(async move {
                if i > 0 {
                    time::sleep(Duration::from_millis(250 * i as u64)).await;
                }

                connect_mptcp_addr(addr)
                    .await
                    .map(|stream| (stream, addr))
                    .inspect_err(|err| error!(%err, %addr, "connect failed"))
            });
        }

        while let Some(res) = futs.next().await {
            if let Ok((stream, addr)) = res {
                debug!(%addr, "connect done");

                return Ok(stream);
            }
        }

        Err(io::Error::new(ErrorKind::Other, "all addrs connect failed"))
    }
}

async gen fn reorder_addrs<S: Stream<Item = io::Result<SocketAddr>>>(
    addrs: S,
) -> io::Result<SocketAddr> {
    let mut v6 = VecDeque::new();
    let mut v4 = VecDeque::new();
    let mut yield_v6 = true;
    let mut addrs = pin!(addrs);

    loop {
        if yield_v6 {
            if let Some(addr) = v6.pop_front() {
                yield_v6 = false;

                yield Ok(addr);
            }

            match addrs.next().await {
                None => return,
                Some(Err(err)) => yield Err(err),
                Some(Ok(addr)) => {
                    if addr.is_ipv4() {
                        v4.push_back(addr);

                        continue;
                    }

                    yield_v6 = false;

                    yield Ok(addr)
                }
            }
        } else {
            if let Some(addr) = v4.pop_front() {
                yield_v6 = true;

                yield Ok(addr);
            }

            match addrs.next().await {
                None => return,
                Some(Err(err)) => yield Err(err),
                Some(Ok(addr)) => {
                    if addr.is_ipv6() {
                        v6.push_back(addr);

                        continue;
                    }

                    yield_v6 = true;

                    yield Ok(addr)
                }
            }
        }
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
