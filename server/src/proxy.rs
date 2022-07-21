use std::io::Error;

use futures_util::{io, try_join, FutureExt};
use futures_util::{AsyncRead, AsyncWrite};
use tap::TapFallible;
use tracing::error;

/// copy data from in_stream to remote_tcp and copy data from remote_tcp to out_stream
pub async fn proxy<RemoteIn, RemoteOut, ClientIn, ClientOut>(
    remote_in_stream: RemoteIn,
    mut remote_out_stream: RemoteOut,
    client_in_stream: ClientIn,
    mut client_out_stream: ClientOut,
) -> Result<(), Error>
where
    RemoteIn: AsyncRead + Unpin + Send + 'static,
    RemoteOut: AsyncWrite + Unpin + Send + 'static,
    ClientIn: AsyncRead + Unpin + Send + 'static,
    ClientOut: AsyncWrite + Unpin + Send + 'static,
{
    let task1 = tokio::spawn(async move {
        io::copy(client_in_stream, &mut remote_out_stream)
            .await
            .tap_err(|err| error!(%err, "copy data from in_stream to tcp failed"))
    })
    .map(|task| task.unwrap());
    let task2 = tokio::spawn(async move {
        io::copy(remote_in_stream, &mut client_out_stream)
            .await
            .tap_err(|err| error!(%err, "copy data from tcp to out_stream failed"))
    })
    .map(|task| task.unwrap());

    try_join!(task1, task2)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};

    use futures_util::io::Cursor;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

    use super::*;

    #[derive(Clone)]
    struct WatchBuf {
        buf: Arc<Mutex<Vec<u8>>>,
    }

    impl AsyncWrite for WatchBuf {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.buf.lock().unwrap().extend_from_slice(buf);

            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn test_proxy() {
        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let in_stream = Cursor::new([1, 2, 3]);
        let out_stream = WatchBuf {
            buf: Arc::new(Mutex::new(vec![])),
        };
        let watch = out_stream.clone();

        let task = tokio::spawn(async move {
            let tcp_stream = TcpStream::connect(addr).await.unwrap();
            let (tcp_in_stream, tcp_out_stream) = tcp_stream.into_split();

            proxy(
                tcp_in_stream.compat(),
                tcp_out_stream.compat_write(),
                in_stream,
                out_stream,
            )
            .await
        });

        let (mut tcp_stream, _) = listener.accept().await.unwrap();

        tcp_stream.write_all(b"test").await.unwrap();

        let mut buf = vec![0; 3];

        tcp_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, [1, 2, 3]);

        drop(tcp_stream);

        task.await.unwrap().unwrap();

        assert_eq!(watch.buf.lock().unwrap().as_slice(), b"test");
    }
}
