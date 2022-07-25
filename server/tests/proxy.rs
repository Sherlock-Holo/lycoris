use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
use futures_util::future::poll_fn;
use futures_util::StreamExt;
use h2::client;
use http::{HeaderMap, HeaderValue, Request};
use server::{Auth, Server};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::{
    Certificate, ClientConfig, OwnedTrustAnchor, PrivateKey, RootCertStore, ServerConfig,
    ServerName,
};
use tokio_rustls::webpki::TrustAnchor;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use totp_rs::{Algorithm, TOTP};
use tracing::level_filters::LevelFilter;
use tracing::{debug, error, subscriber};
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{fmt, Registry};

#[tokio::test]
async fn main() {
    const TOTP_SECRET: &str = "test";
    const TOTP_HEADER: &str = "x-secret";

    init_log();

    let auth = Auth::new(TOTP_SECRET.to_string(), None).unwrap();

    let mut keys = load_keys(Path::new("tests/server.key")).await;
    let certs = load_certs(Path::new("tests/server.cert")).await;
    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, keys.remove(0))
        .unwrap();
    let client_config = create_client_config().await;

    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let mut server = Server::new(TOTP_HEADER, auth, listener, tls_acceptor);

    tokio::spawn(async move {
        if let Err(err) = server.start().await {
            eprintln!("{:?}", err);
        }
    });

    let tcp_stream = TcpStream::connect(addr).await.unwrap();
    let tls_connector = TlsConnector::from(Arc::new(client_config));

    let tls_stream = tls_connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp_stream)
        .await
        .unwrap();

    let (mut send_request, connection) = client::handshake(tls_stream).await.unwrap();
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            error!("{}", err);
        }
    });

    send_request = send_request.ready().await.unwrap();

    let totp = create_totp(TOTP_SECRET.to_string());
    let secret = totp.generate_current().unwrap();

    let mut request = Request::new(());
    request
        .headers_mut()
        .append(TOTP_HEADER, HeaderValue::from_str(&secret).unwrap());

    let (response, mut send_stream) = send_request.send_request(request, false).unwrap();

    let remote_listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let remote_addr = remote_listener.local_addr().unwrap();

    let task = tokio::spawn(async move {
        let (mut accepted_stream, _) = remote_listener.accept().await.unwrap();

        accepted_stream.write_all(b"test").await.unwrap();

        let mut buf = [0; 4];

        accepted_stream.read_exact(&mut buf).await.unwrap();

        debug!("{}", String::from_utf8_lossy(&buf));

        assert_eq!(accepted_stream.read(&mut [0; 1]).await.unwrap(), 0);

        accepted_stream.shutdown().await
    });

    let remote_ip = if let IpAddr::V4(remote_ip) = remote_addr.ip() {
        remote_ip.octets()
    } else {
        panic!("{} is not ipv4", remote_addr.ip());
    };

    send_stream.reserve_capacity(1 + 4 + 2);
    while send_stream.capacity() < 1 + 4 + 2 {
        poll_fn(|cx| send_stream.poll_capacity(cx))
            .await
            .unwrap()
            .unwrap();
    }

    let mut buf = BytesMut::with_capacity(1 + 4 + 2);
    buf.put_u8(4);
    buf.put(remote_ip.as_slice());
    buf.put_u16(remote_addr.port());

    send_stream.send_data(buf.freeze(), false).unwrap();

    let recv_stream = response.await.unwrap();
    let mut recv_stream = recv_stream.into_body();

    let data = recv_stream.next().await.unwrap().unwrap();
    debug!("{}", String::from_utf8_lossy(&data));

    recv_stream
        .flow_control()
        .release_capacity(data.len())
        .unwrap();

    send_stream.reserve_capacity(4);
    while send_stream.capacity() < 4 {
        poll_fn(|cx| send_stream.poll_capacity(cx))
            .await
            .unwrap()
            .unwrap();
    }

    send_stream
        .send_data(Bytes::from_static(b"test"), false)
        .unwrap();
    send_stream.send_trailers(HeaderMap::new()).unwrap();

    debug!("send trailers done");

    task.await.unwrap().unwrap();

    debug!("task done");

    assert!(recv_stream.next().await.is_none());
}

async fn load_certs(path: &Path) -> Vec<Certificate> {
    let certs = fs::read(path).await.unwrap();
    let mut certs = rustls_pemfile::certs(&mut certs.as_slice()).unwrap();

    certs.drain(..).map(Certificate).collect()
}

async fn load_keys(path: &Path) -> Vec<PrivateKey> {
    let keys = fs::read(path).await.unwrap();
    let mut keys = rustls_pemfile::rsa_private_keys(&mut keys.as_slice()).unwrap();

    keys.drain(..).map(PrivateKey).collect()
}

async fn create_client_config() -> ClientConfig {
    let mut root_cert_store = RootCertStore::empty();
    let ca_certs = fs::read("tests/ca.cert").await.unwrap();
    let ca_certs = rustls_pemfile::certs(&mut ca_certs.as_slice()).unwrap();

    let trust_anchors = ca_certs.iter().map(|cert| {
        let trust_anchor = TrustAnchor::try_from_cert_der(cert).unwrap();

        OwnedTrustAnchor::from_subject_spki_name_constraints(
            trust_anchor.subject,
            trust_anchor.spki,
            trust_anchor.name_constraints,
        )
    });

    root_cert_store.add_server_trust_anchors(trust_anchors);

    ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth()
}

fn create_totp(secret: String) -> TOTP<String> {
    TOTP::new(
        Algorithm::SHA512,
        8,
        1,
        30,
        secret,
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
