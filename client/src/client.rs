use std::sync::Arc;

use share::proxy;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use tracing::info;

use crate::connect::Connect;
use crate::err::Error;
use crate::listener::Listener;

pub struct Client<C> {
    connector: Arc<C>,
    listener: Listener,
}

impl<C> Client<C> {
    pub fn new(connector: C, listener: Listener) -> Self {
        Self {
            connector: Arc::new(connector),
            listener,
        }
    }
}

impl<C: Connect + Send + Sync + 'static> Client<C> {
    pub async fn start(&mut self) -> Result<(), Error> {
        loop {
            let (tcp_stream, addr) = if let Ok(result) = self.listener.accept().await {
                result
            } else {
                continue;
            };

            info!(%addr, "accept new tcp stream");

            let connector = self.connector.clone();

            tokio::spawn(async move {
                let (read, write) = connector.connect(addr).await?;

                info!("connect done");

                let (tcp_read, tcp_write) = tcp_stream.into_split();

                proxy::proxy(read, write, tcp_read.compat(), tcp_write.compat_write()).await?;

                Ok::<_, Error>(())
            });
        }
    }
}
