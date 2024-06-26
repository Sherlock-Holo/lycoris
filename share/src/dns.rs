use std::io;
use std::net::IpAddr;

use futures_util::future::join;
use futures_util::{stream, Stream};
use hickory_resolver::name_server::{GenericConnector, TokioRuntimeProvider};
use hickory_resolver::AsyncResolver;
use protocol::DnsResolver;

#[derive(Clone)]
pub struct HickoryDnsResolver {
    resolver: AsyncResolver<GenericConnector<TokioRuntimeProvider>>,
}

impl HickoryDnsResolver {
    pub fn new() -> io::Result<Self> {
        let resolver = AsyncResolver::tokio_from_system_conf()?;

        Ok(Self { resolver })
    }
}

impl DnsResolver for HickoryDnsResolver {
    async fn resolve(
        &mut self,
        name: &str,
    ) -> io::Result<impl Stream<Item = io::Result<IpAddr>> + Send> {
        let (addrs1, addrs2) = join(
            async {
                let addrs = self.resolver.ipv6_lookup(name).await?;
                Ok::<_, io::Error>(addrs.into_iter().map(|addr| IpAddr::from(addr.0)))
            },
            async {
                let addrs = self.resolver.ipv4_lookup(name).await?;
                Ok::<_, io::Error>(addrs.into_iter().map(|addr| IpAddr::from(addr.0)))
            },
        )
        .await;

        let addrs = match (addrs1, addrs2) {
            (Err(err), Err(_)) => return Err(err),
            (addrs1, addrs2) => addrs1
                .ok()
                .into_iter()
                .flatten()
                .chain(addrs2.ok().into_iter().flatten()),
        };

        Ok(stream::iter(addrs.map(Ok)))
    }
}
