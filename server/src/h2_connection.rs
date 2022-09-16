use bytes::Bytes;
use futures_util::future;
use h2::server::{Builder, Connection as H2Connection, SendResponse};
use h2::RecvStream;
use http::Request;
use share::h2_config::*;
use tap::TapFallible;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{error, info};

use crate::Error;

pub struct Connection<IO> {
    h2_connection: H2Connection<IO, Bytes>,
}

impl<IO> Connection<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn handshake(io: IO) -> Result<Self, Error> {
        let h2_connection = Builder::new()
            .initial_window_size(INITIAL_WINDOW_SIZE)
            .initial_connection_window_size(INITIAL_CONNECTION_WINDOW_SIZE)
            .max_frame_size(MAX_FRAME_SIZE)
            .handshake(io)
            .await
            .tap_err(|err| error!(%err, "http/2 handshake failed"))?;

        info!("http/2 handshake done");

        Ok(Self { h2_connection })
    }

    pub async fn accept_h2_stream(
        &mut self,
    ) -> Option<Result<(Request<RecvStream>, SendResponse<Bytes>), Error>> {
        let result = self.h2_connection.accept().await?;

        Some(result.map_err(Into::into))
    }

    pub async fn close(mut self) {
        let _ = future::poll_fn(|cx| self.h2_connection.poll_closed(cx)).await;
    }
}
