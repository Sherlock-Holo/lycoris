use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use async_trait::async_trait;
use bytes::{Buf, BytesMut};
use futures_channel::mpsc;
use futures_channel::mpsc::{Receiver, Sender};
use futures_util::{SinkExt, StreamExt};
use tap::TapFallible;
use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::TcpListenerStream;
use tracing::{error, info, instrument};

use super::Listener;
use crate::addr::domain_or_socket_addr::DomainOrSocketAddr;
use crate::Error;

#[derive(Debug)]
pub struct SocksListener {
    connection_stream: Receiver<(BufStream<TcpStream>, DomainOrSocketAddr)>,
    task: JoinHandle<()>,
}

impl SocksListener {
    pub async fn new(addr: SocketAddr) -> io::Result<Self> {
        let tcp_listener = TcpListener::bind(addr)
            .await
            .tap_err(|err| error!(%err, %addr, "bind addr failed"))?;
        let (sender, connection_stream) = mpsc::channel(10);

        let task = tokio::spawn(async move { accept_tcp(sender, tcp_listener).await });

        Ok(Self {
            connection_stream,
            task,
        })
    }
}

#[async_trait]
impl Listener for SocksListener {
    type Stream = BufStream<TcpStream>;

    #[instrument(err)]
    async fn accept(&mut self) -> Result<(Self::Stream, DomainOrSocketAddr), Error> {
        let task = &mut self.task;

        let result = tokio::select! {
            _ = task => {
                error!("socks listener stopped unexpected");

                return Err(crate::Error::Other("socks listener stopped unexpected".into()));
            }

            result = self.connection_stream.next() => result
        };

        match result {
            None => {
                error!("receive tcp stream and addr failed");

                return Err(Error::Other("receive tcp stream and addr failed".into()));
            }

            Some(result) => Ok(result),
        }
    }
}

async fn accept_tcp(
    sender: Sender<(BufStream<TcpStream>, DomainOrSocketAddr)>,
    tcp_listener: TcpListener,
) {
    let mut listener_stream = TcpListenerStream::new(tcp_listener);

    while let Some(result) = listener_stream.next().await {
        let tcp_stream = match result {
            Err(err) => {
                error!(%err, "accept tcp stream failed");

                continue;
            }

            Ok(tcp_stream) => tcp_stream,
        };
        let sender = sender.clone();

        tokio::spawn(async move { socks_handshake(tcp_stream, sender).await });
    }
}

#[instrument]
async fn socks_handshake(
    tcp_stream: TcpStream,
    mut sender: Sender<(BufStream<TcpStream>, DomainOrSocketAddr)>,
) {
    const IPV6_SIZE: usize = size_of::<u128>();

    let mut stream = BufStream::new(tcp_stream);

    match stream.read_u8().await {
        Err(err) => {
            error!(%err, "read socks version failed");

            return;
        }

        Ok(ver) => {
            if ver != 5 {
                error!(ver, "socks version unsupported");

                return;
            }

            info!(ver, "read socks version done");
        }
    }

    let mut count = match stream.read_u8().await {
        Err(err) => {
            error!(%err, "read socks method count failed");

            return;
        }

        Ok(count) => {
            info!(count, "read socks count done");

            count as usize
        }
    };

    let mut buf = BytesMut::with_capacity(count);
    while count > 0 {
        match stream.read_buf(&mut buf).await {
            Err(err) => {
                error!(%err, "read socks methods failed");

                return;
            }

            Ok(n) => {
                count -= n;
            }
        }
    }

    let mut support_unauthorized = false;
    while buf.has_remaining() {
        // unauthorized mode
        if buf.get_u8() == 0 {
            support_unauthorized = true;

            break;
        }
    }

    if !support_unauthorized {
        error!("socks peer not supported unauthorized mode");

        let _ = stream.write_all(&[5, 0xff]).await;

        return;
    }

    if let Err(err) = stream.write_all(&[5, 0]).await {
        error!(%err, "write socks handshake reply failed");

        return;
    }

    if let Err(err) = stream.flush().await {
        error!(%err, "flush stream failed");

        return;
    }

    match stream.read_u8().await {
        Err(err) => {
            error!(%err, "read socks version again failed");

            return;
        }

        Ok(ver) => {
            if ver != 5 {
                error!(ver, "socks version unsupported");

                return;
            }

            info!(ver, "read socks version again done");
        }
    }

    match stream.read_u8().await {
        Err(err) => {
            error!(%err, "read socks cmd failed");

            return;
        }

        Ok(cmd) => {
            if cmd != 1 {
                error!(cmd, "unsupported socks cmd");

                let _ = stream.write_all(&[5, 0x07, 0x00]).await;

                return;
            }
        }
    }

    if let Err(err) = stream.read_exact(&mut [0; 1]).await {
        error!(%err, "skip socks rsv failed");

        return;
    }

    buf.clear();
    let addr = match stream.read_u8().await {
        Err(err) => {
            error!(%err, "read socks addr type failed");

            return;
        }

        Ok(1) => {
            let mut n = 4 + 2;
            buf.reserve(n);

            while n > 0 {
                match stream.read_buf(&mut buf).await {
                    Err(err) => {
                        error!(%err, "read socks ipv4 addr failed");

                        return;
                    }

                    Ok(read) => {
                        n -= read;
                    }
                }
            }

            let addr: [u8; 4] = buf.get(0..4).unwrap().try_into().unwrap();
            buf.advance(4);
            let port = buf.get_u16();

            DomainOrSocketAddr::SocketAddr(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(addr),
                port,
            )))
        }

        Ok(4) => {
            let mut n = IPV6_SIZE + 2;
            buf.reserve(n);

            while n > 0 {
                match stream.read_buf(&mut buf).await {
                    Err(err) => {
                        error!(%err, "read socks ipv6 addr failed");

                        return;
                    }

                    Ok(read) => {
                        n -= read;
                    }
                }
            }

            let addr: [u8; IPV6_SIZE] = buf.get(0..IPV6_SIZE).unwrap().try_into().unwrap();
            buf.advance(IPV6_SIZE);
            let port = buf.get_u16();

            DomainOrSocketAddr::SocketAddr(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(addr),
                port,
                0,
                0,
            )))
        }

        Ok(3) => {
            let len = match stream.read_u8().await {
                Err(err) => {
                    error!(%err, "read domain len failed");

                    return;
                }

                Ok(len) => len as usize,
            };
            let mut n = len + 2;

            buf.reserve(n);

            while n > 0 {
                match stream.read_buf(&mut buf).await {
                    Err(err) => {
                        error!(%err, "read socks domain addr failed");

                        return;
                    }

                    Ok(read) => {
                        n -= read;
                    }
                }
            }

            let domain = buf.get(0..len).unwrap();
            let domain = match String::from_utf8(domain.to_vec()) {
                Err(err) => {
                    error!(%err, "domain invalid");

                    let _ = stream.write_all(&[5, 0x04, 0, 1, 127, 0, 0, 1, 0, 0]).await;

                    return;
                }

                Ok(domain) => domain,
            };

            buf.advance(len);
            let port = buf.get_u16();

            DomainOrSocketAddr::Domain { domain, port }
        }

        Ok(addr_type) => {
            error!(addr_type, "invalid addr type");

            let _ = stream.write_all(&[5, 0x08, 0]).await;

            return;
        }
    };

    info!(?addr, "read socks addr done");

    match &addr {
        DomainOrSocketAddr::SocketAddr(SocketAddr::V4(_)) | DomainOrSocketAddr::Domain { .. } => {
            if let Err(err) = stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1]).await {
                error!(?addr, %err, "send ipv4 or domain socks reply failed");

                return;
            }
        }

        DomainOrSocketAddr::SocketAddr(SocketAddr::V6(_)) => {
            if let Err(err) = stream.write_all(&[5, 0, 0, 4]).await {
                error!(?addr, %err, "send ipv6 socks reply prefix failed");

                return;
            }

            if let Err(err) = stream
                .write_all(&Ipv6Addr::from([0, 0, 0, 0, 0, 0, 0, 1]).octets())
                .await
            {
                error!(?addr, %err, "send ipv6 socks reply addr failed");

                return;
            }

            if let Err(err) = stream.write_u16(1).await {
                error!(?addr, %err, "send ipv6 socks reply port failed");

                return;
            }
        }
    }

    if let Err(err) = stream.flush().await {
        error!(%err, "flush socks reply failed");

        return;
    }

    if let Err(err) = sender.send((stream, addr)).await {
        error!(%err, "send tcp stream and addr failed");
    } else {
        info!("send tcp stream and addr done");
    }
}
