use std::convert::Infallible;
use std::sync::Arc;

use anyhow::Context;
use bytes::Bytes;
use futures_channel::mpsc;
use http::{Request, StatusCode, Uri, Version};
use http_body_util::combinators::BoxBody;
use http_body_util::StreamBody;
use hyper::body::Frame;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use share::h2_config::{
    INITIAL_CONNECTION_WINDOW_SIZE, INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE, PING_INTERVAL,
    PING_TIMEOUT,
};
use share::hyper_body::{BodyStream, SinkBodySender};
use tokio_rustls::rustls::ClientConfig;
use tokio_util::io::{SinkWriter, StreamReader};
use tracing::{error, info, instrument};

use super::Connect;
use crate::addr::domain_or_socket_addr::DomainOrSocketAddr;
use crate::{addr, TokenGenerator};

#[derive(Debug, Clone)]
pub struct HyperConnector {
    inner: Arc<HyperConnectorInner>,
}

#[derive(Debug)]
struct HyperConnectorInner {
    client: Client<HttpsConnector<HttpConnector>, BoxBody<Bytes, Infallible>>,
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
    ) -> anyhow::Result<Self> {
        let https_connector = HttpsConnectorBuilder::new()
            .with_tls_config(client_config)
            .https_only()
            .with_server_name(remote_domain.to_string())
            .enable_http2()
            .build();

        let client = Client::builder(TokioExecutor::new())
            .timer(TokioTimer::new())
            .http2_only(true)
            .http2_initial_connection_window_size(INITIAL_WINDOW_SIZE)
            .http2_initial_connection_window_size(INITIAL_CONNECTION_WINDOW_SIZE)
            .http2_max_frame_size(MAX_FRAME_SIZE)
            .http2_keep_alive_timeout(PING_TIMEOUT)
            .http2_keep_alive_interval(PING_INTERVAL)
            .build(https_connector);

        Ok(Self {
            inner: Arc::new(HyperConnectorInner {
                client,
                remote_addr: Uri::try_from(format!("https://{}:{}", remote_domain, remote_port))?,
                token_generator,
                token_header: token_header.to_string(),
            }),
        })
    }
}

impl Connect for HyperConnector {
    type Read = StreamReader<BodyStream, Bytes>;
    type Write = SinkWriter<SinkBodySender<Infallible>>;

    #[instrument(err(Debug))]
    async fn connect(
        &self,
        remote_addr: DomainOrSocketAddr,
    ) -> anyhow::Result<(Self::Read, Self::Write)> {
        let token = self.inner.token_generator.generate_token();
        let remote_addr_data = addr::encode_addr(remote_addr);

        let (req_body_tx, req_body_rx) = mpsc::unbounded();
        req_body_tx
            .unbounded_send(Ok(Frame::data(remote_addr_data)))
            .expect("unbounded_send should not fail");

        let request = Request::builder()
            .version(Version::HTTP_2)
            .uri(self.inner.remote_addr.clone())
            .header(&self.inner.token_header, token)
            .body(BoxBody::new(StreamBody::new(req_body_rx)))
            .with_context(|| "build h2 request failed")?;

        let response = self
            .inner
            .client
            .request(request)
            .await
            .with_context(|| "send h2 request failed")?;

        info!("receive h2 response done");

        if response.status() != StatusCode::OK {
            let status_code = response.status();
            error!(%status_code, "status code is not 200");

            return Err(anyhow::anyhow!("status {status_code} is not 200"));
        }

        info!("get h2 stream done");

        let reader = StreamReader::new(BodyStream::from(response.into_body()));

        Ok((reader, SinkWriter::new(req_body_tx.into())))
    }
}
