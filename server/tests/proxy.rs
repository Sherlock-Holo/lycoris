use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
use futures_util::StreamExt;
use http::{HeaderMap, HeaderValue, Request, Uri};
use hyper::{Body, Client};
use hyper_rustls::HttpsConnectorBuilder;
use lycoris_server::{Auth, HyperServer};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::TlsAcceptor;
use totp_rs::{Algorithm, TOTP};
use tracing::level_filters::LevelFilter;
use tracing::{debug, subscriber};
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{fmt, Registry};

#[tokio::test]
async fn main() {
    const TOTP_SECRET: &str = "test-secrettest-secret";
    const TOTP_HEADER: &str = "x-secret";

    init_log();

    let auth = Auth::new(TOTP_SECRET.to_string(), None).unwrap();

    let mut keys = load_keys(Path::new("tests/server.key")).await;
    let certs = load_certs(Path::new("tests/server.cert")).await;
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, keys.remove(0).into())
        .unwrap();
    let client_config = create_client_config().await;

    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let mut server = HyperServer::new(TOTP_HEADER, auth, listener, tls_acceptor);

    tokio::spawn(async move {
        if let Err(err) = server.start().await {
            eprintln!("{:?}", err);
        }
    });

    let https_connector = HttpsConnectorBuilder::new()
        .with_tls_config(client_config)
        .https_only()
        .with_server_name("localhost".to_string())
        .enable_http2()
        .build();
    let client = Client::builder().http2_only(true).build(https_connector);

    let totp = create_totp(TOTP_SECRET.to_string());
    let secret = totp.generate_current().unwrap();

    let remote_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let remote_addr = remote_listener.local_addr().unwrap();

    let task = tokio::spawn(async move {
        let (mut accepted_stream, _) = remote_listener.accept().await.unwrap();

        accepted_stream.write_all(b"test").await.unwrap();

        let mut buf = [0; 4];

        accepted_stream.read_exact(&mut buf).await.unwrap();

        assert_eq!(&buf, b"test");
        assert_eq!(accepted_stream.read(&mut [0; 1]).await.unwrap(), 0);
    });

    let remote_ip = if let IpAddr::V4(remote_ip) = remote_addr.ip() {
        remote_ip.octets()
    } else {
        panic!("{} is not ipv4", remote_addr.ip());
    };

    let (mut sender, body) = Body::channel();
    let mut request = Request::new(body);
    *request.uri_mut() = Uri::try_from(format!("https://localhost:{}", addr.port())).unwrap();
    request
        .headers_mut()
        .append(TOTP_HEADER, HeaderValue::from_str(&secret).unwrap());

    let mut buf = BytesMut::with_capacity(1 + 4 + 2);
    buf.put_u8(4);
    buf.put(remote_ip.as_slice());
    buf.put_u16(remote_addr.port());

    sender.send_data(buf.freeze()).await.unwrap();

    let response = client.request(request).await.unwrap();

    let mut recv_stream = response.into_body();

    let data = recv_stream.next().await.unwrap().unwrap();
    assert_eq!(data.as_ref(), b"test");

    sender.send_data(Bytes::from_static(b"test")).await.unwrap();
    sender.send_trailers(HeaderMap::new()).await.unwrap();

    debug!("send trailers done");

    drop(sender);

    task.await.unwrap();

    debug!("task done");

    assert!(recv_stream.next().await.is_none());
}

async fn load_certs(path: &Path) -> Vec<CertificateDer> {
    let certs = fs::read(path).await.unwrap();

    rustls_pemfile::certs(&mut certs.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

async fn load_keys(path: &Path) -> Vec<PrivatePkcs8KeyDer> {
    let keys = fs::read(path).await.unwrap();

    rustls_pemfile::pkcs8_private_keys(&mut keys.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

async fn create_client_config() -> ClientConfig {
    let mut root_cert_store = RootCertStore::empty();
    let ca_certs = fs::read("tests/ca.cert").await.unwrap();

    for ca_cert in rustls_pemfile::certs(&mut ca_certs.as_slice()) {
        root_cert_store.add(ca_cert.unwrap()).unwrap();
    }

    ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth()
}

fn create_totp(secret: String) -> TOTP {
    TOTP::new(
        Algorithm::SHA512,
        8,
        1,
        30,
        secret.into(),
        None,
        "default_account".to_string(),
    )
    .unwrap()
}

fn init_log() {
    let layer = fmt::layer()
        .pretty()
        .with_target(true)
        .with_writer(io::stderr);
    let targets = Targets::new()
        .with_target("h2", LevelFilter::OFF)
        .with_default(LevelFilter::DEBUG);
    let layered = Registry::default()
        .with(targets)
        .with(layer)
        .with(LevelFilter::DEBUG);

    subscriber::set_global_default(layered).unwrap();
}
