use std::io;
use std::net::IpAddr;

use futures_util::{stream, Stream, StreamExt};
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
        let lookup_ip = self.resolver.lookup_ip(name).await?;

        Ok(stream::iter(lookup_ip).map(Ok))
    }
}
