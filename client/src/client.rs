use std::sync::Arc;

use share::proxy;
use tracing::info;

use crate::connect::Connect;
use crate::err::Error;
use crate::listener::{Listener, Split};

pub struct Client<C, L> {
    connector: Arc<C>,
    listener: L,
}

impl<C, L> Client<C, L> {
    pub fn new(connector: C, listener: L) -> Self {
        Self {
            connector: Arc::new(connector),
            listener,
        }
    }
}

impl<C, L> Client<C, L>
where
    C: Connect + Send + Sync + 'static,
    L: Listener + Send,
    L::Stream: Send + 'static,
{
    pub async fn start(&mut self) -> Result<(), Error> {
        loop {
            let (tcp_stream, addr) = if let Ok(result) = self.listener.accept().await {
                result
            } else {
                continue;
            };

            info!(?addr, "accept new tcp stream");

            let connector = self.connector.clone();

            tokio::spawn(async move {
                let (read, write) = connector.connect(addr).await?;

                info!("connect done");

                let (tcp_read, tcp_write) = tcp_stream.into_split();

                proxy::proxy(read, write, tcp_read, tcp_write).await?;

                Ok::<_, Error>(())
            });
        }
    }
}
