use std::convert::Infallible;
use std::net::IpAddr;
use std::path::Path;

use bytes::{BufMut, Bytes, BytesMut};
use futures_channel::mpsc;
use futures_rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use futures_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use futures_util::SinkExt;
use http::{HeaderMap, HeaderValue, Request, Uri};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use hyper_rustls::{FixedServerNameResolver, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use lycoris_server::{HyperServer, MptcpListenerExt};
use protocol::auth::Auth;
use share::log::init_log;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use totp_rs::{Algorithm, TOTP};
use tracing::debug;

#[tokio::test]
async fn main() {
    const TOTP_SECRET: &str = "test-secrettest-secret";
    const TOTP_HEADER: &str = "x-secret";

    init_log(true);

    let auth = Auth::new(TOTP_SECRET.to_string(), None).unwrap();

    let mut keys = load_keys(Path::new("tests/server.key")).await;
    let certs = load_certs(Path::new("tests/server.cert")).await;
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, keys.remove(0).into())
        .unwrap();
    let client_config = create_client_config().await;

    let listener = TcpListener::listen_mptcp("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let server = HyperServer::new(TOTP_HEADER.to_string(), auth, listener, server_config).unwrap();

    tokio::spawn(async move {
        if let Err(err) = server.start().await {
            eprintln!("{:?}", err);
        }
    });

    let https_connector = HttpsConnectorBuilder::new()
        .with_tls_config(client_config)
        .https_only()
        .with_server_name_resolver(FixedServerNameResolver::new(
            "localhost".try_into().unwrap(),
        ))
        .enable_http2()
        .build();
    let client = Client::builder(TokioExecutor::new())
        .timer(TokioTimer::new())
        .http2_only(true)
        .build(https_connector);

    let totp = create_totp(TOTP_SECRET.to_string());
    let secret = totp.generate_current().unwrap();

    let remote_listener = TcpListener::listen_mptcp("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
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

    let (mut tx, rx) = mpsc::unbounded();
    let mut request = Request::new(StreamBody::new(rx));
    *request.uri_mut() = Uri::try_from(format!("https://localhost:{}", addr.port())).unwrap();
    request
        .headers_mut()
        .append(TOTP_HEADER, HeaderValue::from_str(&secret).unwrap());

    let mut buf = BytesMut::with_capacity(1 + 4 + 2);
    buf.put_u8(4);
    buf.put(remote_ip.as_slice());
    buf.put_u16(remote_addr.port());

    tx.send(Ok::<_, Infallible>(Frame::data(buf.freeze())))
        .await
        .unwrap();

    let response = client.request(request).await.unwrap();

    let mut recv_stream = response.into_body();

    let data = recv_stream
        .frame()
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(data.as_ref(), b"test");

    tx.send(Ok(Frame::data(Bytes::from_static(b"test"))))
        .await
        .unwrap();
    tx.send(Ok(Frame::trailers(HeaderMap::new())))
        .await
        .unwrap();

    debug!("send trailers done");

    drop(tx);

    task.await.unwrap();

    debug!("task done");

    let trailers = recv_stream
        .frame()
        .await
        .unwrap()
        .unwrap()
        .into_trailers()
        .unwrap();
    assert!(trailers.is_empty());
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
