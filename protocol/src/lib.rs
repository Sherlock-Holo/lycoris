use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::{io, slice};

pub use accept::{HyperAcceptor, HyperListener};
use bytes::{BufMut, Bytes, BytesMut};
pub use connect::{HyperConnector, HyperConnectorConfig};
use futures_rustls::TlsStream;
use futures_util::{AsyncRead, AsyncWrite};
use hyper::rt::ReadBufCursor;
use hyper_util::client::legacy::connect::{Connected, Connection};
use tokio_util::io::{SinkWriter, StreamReader};

use crate::hyper_body::{BodyStream, SinkBodySender};

pub mod accept;
pub mod auth;
pub mod connect;
mod h2_config;
mod hyper_body;

pub type Reader = StreamReader<BodyStream, Bytes>;
pub type Writer = SinkWriter<SinkBodySender<Infallible>>;

#[trait_make::make(Send)]
pub trait DnsResolver: Clone {
    async fn resolve(&mut self, name: &str) -> io::Result<impl IntoIterator<Item = IpAddr>>;
}

#[derive(Debug, Clone)]
pub enum DomainOrSocketAddr {
    Domain { domain: String, port: u16 },

    SocketAddr(SocketAddr),
}

impl From<SocketAddr> for DomainOrSocketAddr {
    fn from(value: SocketAddr) -> Self {
        Self::SocketAddr(value)
    }
}

/// Encode addr to \[addr_type:1, addr:variant, port:2\]
fn encode_addr(addr: impl Into<DomainOrSocketAddr>) -> Bytes {
    match addr.into() {
        DomainOrSocketAddr::Domain { domain, port } => {
            let mut buf = BytesMut::with_capacity(1 + 2 + domain.as_bytes().len() + 2);

            buf.put_u8(1);
            buf.put_u16(domain.as_bytes().len() as _);
            buf.put(domain.as_bytes());
            buf.put_u16(port);

            buf.freeze()
        }
        DomainOrSocketAddr::SocketAddr(addr) => match addr {
            SocketAddr::V4(v4_addr) => {
                let mut buf = BytesMut::with_capacity(1 + 4 + 2);

                buf.put_u8(4);
                buf.put(v4_addr.ip().octets().as_slice());
                buf.put_u16(v4_addr.port());

                buf.freeze()
            }

            SocketAddr::V6(v6_addr) => {
                let mut buf = BytesMut::with_capacity(1 + 16 + 2);

                buf.put_u8(6);
                buf.put(v6_addr.ip().octets().as_slice());
                buf.put_u16(v6_addr.port());

                buf.freeze()
            }
        },
    }
}

pub struct GenericTlsStream<IO> {
    tls_stream: TlsStream<IO>,
}

impl<IO: Connection> Connection for GenericTlsStream<IO> {
    fn connected(&self) -> Connected {
        self.tls_stream.get_ref().0.connected()
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> hyper::rt::Read for GenericTlsStream<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        // Safety: we won't read it, unless IO implement is stupid:(
        let buf_mut = unsafe {
            let buf_mut = buf.as_mut();
            slice::from_raw_parts_mut(buf_mut.as_mut_ptr().cast(), buf_mut.len())
        };

        let n = ready!(Pin::new(&mut self.tls_stream).poll_read(cx, buf_mut))?;

        // Safety: n is written
        unsafe {
            buf.advance(n);
        }

        Poll::Ready(Ok(()))
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> hyper::rt::Write for GenericTlsStream<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.tls_stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tls_stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tls_stream).poll_close(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;
    use std::str::FromStr;

    use super::*;

    #[test]
    fn encode_v4() {
        let data = encode_addr(SocketAddr::from_str("127.0.0.1:80").unwrap());

        let mut correct = BytesMut::from(&[4, 127, 0, 0, 1][..]);
        correct.put_u16(80);

        assert_eq!(data, correct);
    }

    #[test]
    fn encode_v6() {
        let data = encode_addr(SocketAddr::from_str("[::1]:80").unwrap());

        let mut correct = BytesMut::from(&[6][..]);
        correct.put(Ipv6Addr::from_str("::1").unwrap().octets().as_slice());
        correct.put_u16(80);

        assert_eq!(data, correct);
    }

    #[test]
    fn encode_domain() {
        let data = encode_addr(DomainOrSocketAddr::Domain {
            domain: "www.example.com".to_string(),
            port: 80,
        });

        let mut correct = BytesMut::from(&[1][..]);
        correct.put_u16("www.example.com".as_bytes().len() as _);
        correct.put("www.example.com".as_bytes());
        correct.put_u16(80);

        assert_eq!(data, correct);
    }
}
