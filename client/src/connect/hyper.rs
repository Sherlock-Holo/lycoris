use std::io;
use std::io::ErrorKind;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http::{Request, StatusCode, Uri, Version};
use hyper::client::HttpConnector;
use hyper::{Body, Client};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use share::h2_config::{INITIAL_CONNECTION_WINDOW_SIZE, INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE};
use share::hyper_body::{BodyStream, SinkBodySender};
use tap::TapFallible;
use tokio_rustls::rustls::ClientConfig;
use tokio_util::io::{SinkWriter, StreamReader};
use tracing::{error, info, instrument};

use super::Connect;
use crate::addr::domain_or_socket_addr::DomainOrSocketAddr;
use crate::{addr, Error, TokenGenerator};

#[derive(Debug, Clone)]
pub struct HyperConnector {
    inner: Arc<HyperConnectorInner>,
}

#[derive(Debug)]
struct HyperConnectorInner {
    client: Client<HttpsConnector<HttpConnector>>,
    remote_addr: Uri,
    token_generator: TokenGenerator,
    token_header: String,
}

impl HyperConnector {
    pub fn new(
        client_config: ClientConfig,
        remote_domain: &str,
        remote_port: u16,
        token_generator: TokenGenerator,
        token_header: &str,
    ) -> Result<Self, Error> {
        let https_connector = HttpsConnectorBuilder::new()
            .with_tls_config(client_config)
            .https_only()
            .with_server_name(remote_domain.to_string())
            .enable_http2()
            .build();

        let client = Client::builder()
            .http2_only(true)
            .http2_initial_connection_window_size(INITIAL_WINDOW_SIZE)
            .http2_initial_connection_window_size(INITIAL_CONNECTION_WINDOW_SIZE)
            .http2_max_frame_size(MAX_FRAME_SIZE)
            .build(https_connector);

        Ok(Self {
            inner: Arc::new(HyperConnectorInner {
                client,
                remote_addr: Uri::try_from(format!("https://{}:{}", remote_domain, remote_port))
                    .map_err(|err| Error::Other(err.into()))?,
                token_generator,
                token_header: token_header.to_string(),
            }),
        })
    }
}

#[async_trait]
impl Connect for HyperConnector {
    type Read = StreamReader<BodyStream, Bytes>;
    type Write = SinkWriter<SinkBodySender>;

    #[instrument(err)]
    async fn connect(
        &self,
        remote_addr: DomainOrSocketAddr,
    ) -> Result<(Self::Read, Self::Write), Error> {
        let token = self.inner.token_generator.generate_token();
        let remote_addr_data = addr::encode_addr(remote_addr);

        let (mut sender, body) = Body::channel();
        if sender.try_send_data(remote_addr_data).is_err() {
            error!("send remote addr data failed");

            return Err(Error::Other("send remote addr data failed".into()));
        }

        let writer = SinkWriter::new(SinkBodySender::new(sender));

        let request = Request::builder()
            .version(Version::HTTP_2)
            .uri(self.inner.remote_addr.clone())
            .header(&self.inner.token_header, token)
            .body(body)
            .map_err(|err| {
                error!(%err, "build h2 request failed");

                Error::Other(err.into())
            })?;

        let response = self
            .inner
            .client
            .request(request)
            .await
            .tap_err(|err| error!(%err, "send h2 request failed"))?;

        info!("receive h2 response done");

        if response.status() != StatusCode::OK {
            let status_code = response.status();
            error!(%status_code, "status code is not 200");

            return Err(Error::Io(io::Error::new(
                ErrorKind::Other,
                format!("status {} is not 200", status_code),
            )));
        }

        info!("get h2 stream done");

        let reader = StreamReader::new(BodyStream::new(response.into_body()));

        Ok((reader, writer))
    }
}
