use std::io;
use std::io::ErrorKind;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::future;
use h2::server::{Builder, Connection as H2Connection, SendResponse};
use h2::RecvStream;
use http::Request;
use share::h2_config::*;
use share::h2_ping::{self, AbortType};
use tap::TapFallible;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::select;
use tokio::sync::Notify;
use tracing::{error, info};

use crate::Error;

pub struct Connection<IO> {
    h2_connection: H2Connection<IO, Bytes>,
    notify: Arc<Notify>,
}

impl<IO> Connection<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn handshake(io: IO) -> Result<Self, Error> {
        let mut h2_connection = Builder::new()
            .initial_window_size(INITIAL_WINDOW_SIZE)
            .initial_connection_window_size(INITIAL_CONNECTION_WINDOW_SIZE)
            .max_frame_size(MAX_FRAME_SIZE)
            .handshake(io)
            .await
            .tap_err(|err| error!(%err, "http/2 handshake failed"))?;

        info!("http/2 handshake done");

        let ping_pong = h2_connection.ping_pong().expect("ping_pong return None");
        let notify = Arc::new(Notify::new());

        {
            let notify = notify.clone();
            tokio::spawn(async move {
                h2_ping::h2_connection_ping_pong(ping_pong, AbortType::Notify(notify)).await
            });
        }

        Ok(Self {
            h2_connection,
            notify,
        })
    }

    pub async fn accept_h2_stream(
        &mut self,
    ) -> Option<Result<(Request<RecvStream>, SendResponse<Bytes>), Error>> {
        let result = select! {
            result = self.h2_connection.accept() => {
                result?
            }

            _ = self.notify.notified() => {
                error!("server h2 connection ping pong timeout");

                return Some(Err(Error::Io(io::Error::from(ErrorKind::TimedOut))));
            }
        };

        Some(result.map_err(Into::into))
    }

    pub async fn close(mut self) {
        let _ = future::poll_fn(|cx| self.h2_connection.poll_closed(cx)).await;
    }
}
