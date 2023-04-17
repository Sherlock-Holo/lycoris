use std::io::{self, ErrorKind};
use std::sync::Arc;
use std::time::Duration;

use share::proxy;
use tokio::time;
use tracing::{error, info, instrument};

use crate::addr::domain_or_socket_addr::DomainOrSocketAddr;
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

            tokio::spawn(handle_proxy(connector, addr, tcp_stream));
        }
    }
}

#[instrument(skip(connector, tcp_stream), err)]
async fn handle_proxy<C: Connect, S: Split + 'static>(
    connector: Arc<C>,
    addr: DomainOrSocketAddr,
    tcp_stream: S,
) -> Result<(), Error> {
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    let (read, write) = match time::timeout(CONNECT_TIMEOUT, connector.connect(addr)).await {
        Err(err) => {
            error!(%err, "connect timeout");

            return Err(Error::Io(io::Error::new(ErrorKind::TimedOut, err)));
        }

        Ok(result) => result?,
    };

    info!("connect done");

    let (tcp_read, tcp_write) = tcp_stream.into_split();

    proxy::proxy(read, write, tcp_read, tcp_write).await?;

    Ok::<_, Error>(())
}
