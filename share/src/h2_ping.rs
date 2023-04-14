use std::sync::Arc;

use futures_util::future::AbortHandle;
use futures_util::StreamExt;
use h2::{Ping, PingPong};
use tokio::sync::Notify;
use tokio::time;
use tokio_stream::wrappers::IntervalStream;
use tracing::error;

use crate::h2_config::{PING_INTERVAL, TIMEOUT};

#[derive(Debug)]
pub enum AbortType {
    Handle(AbortHandle),
    Notify(Arc<Notify>),
}

pub async fn h2_connection_ping_pong(mut ping_pong: PingPong, abort_handle: AbortType) {
    let mut interval_stream = IntervalStream::new(time::interval(PING_INTERVAL));

    while interval_stream.next().await.is_some() {
        match time::timeout(TIMEOUT, ping_pong.ping(Ping::opaque())).await {
            Err(_) => {
                error!("h2 connection ping timeout");

                match abort_handle {
                    AbortType::Handle(handle) => handle.abort(),
                    AbortType::Notify(notify) => notify.notify_one(),
                }

                return;
            }

            Ok(Err(err)) => {
                error!(%err, "h2 connection ping failed");

                match abort_handle {
                    AbortType::Handle(handle) => handle.abort(),
                    AbortType::Notify(notify) => notify.notify_one(),
                }

                return;
            }

            Ok(Ok(_)) => {}
        }
    }
}
