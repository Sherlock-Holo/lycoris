use std::convert::Infallible;
use std::io;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;

use async_trait::async_trait;
use bytes::Bytes;
use futures_channel::mpsc;
use futures_channel::mpsc::{Receiver, Sender};
use futures_util::{SinkExt, StreamExt};
use http::{Method, Request, Response, StatusCode};
use http_body::Empty;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::upgrade::Upgraded;
use hyper::{upgrade, Server};
use tokio::task::JoinHandle;
use tracing::{error, info, instrument};

use super::Listener;
use crate::addr::domain_or_socket_addr::DomainOrSocketAddr;

pub struct HttpListener {
    task: JoinHandle<()>,
    connection_stream: Receiver<(Upgraded, DomainOrSocketAddr)>,
}

impl HttpListener {
    pub async fn new(addr: SocketAddr) -> io::Result<Self> {
        let (sender, connection_stream) = mpsc::channel(10);
        let task = start_http_server(sender, &addr);

        Ok(Self {
            task,
            connection_stream,
        })
    }
}

#[async_trait]
impl Listener for HttpListener {
    type Stream = Upgraded;

    async fn accept(&mut self) -> Result<(Self::Stream, DomainOrSocketAddr), crate::Error> {
        let task = &mut self.task;

        let result = tokio::select! {
            _ = task => {
                error!("http proxy listener stopped unexpected");

                return Err(crate::Error::Other("http proxy listener stopped unexpected".into()));
            }

            result = self.connection_stream.next() => result
        };

        match result {
            None => {
                error!("receive tcp stream and addr failed");

                return Err(crate::Error::Other(
                    "receive tcp stream and addr failed".into(),
                ));
            }

            Some(result) => Ok(result),
        }
    }
}

fn start_http_server(
    sender: Sender<(Upgraded, DomainOrSocketAddr)>,
    addr: &SocketAddr,
) -> JoinHandle<()> {
    let server = Server::bind(addr).serve(make_service_fn(move |conn: &AddrStream| {
        let sender = sender.clone();
        let remote_addr = conn.remote_addr();

        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let mut sender = sender.clone();

                async move {
                    let (response, target) = handle_connect_request(&req, remote_addr);
                    if let Some(target) = target {
                        tokio::spawn(async move {
                            let upgraded = upgrade(req, remote_addr).await?;

                            if let Err(err) = sender.send((upgraded, target.clone())).await {
                                error!(%err, "send http connect upgraded failed");

                                Err(Error::new(ErrorKind::Other, err))
                            } else {
                                info!(?target, "send http connect upgraded done");

                                Ok(())
                            }
                        });
                    }

                    Ok::<_, Infallible>(response)
                }
            }))
        }
    }));

    tokio::spawn(async move {
        if let Err(err) = server.await {
            error!(%err, "http proxy stop unexpected");
        }
    })
}

#[instrument(skip(request))]
fn handle_connect_request<B>(
    request: &Request<B>,
    remote_addr: SocketAddr,
) -> (Response<Empty<Bytes>>, Option<DomainOrSocketAddr>) {
    let mut response = Response::new(Empty::new());

    if request.method() != Method::CONNECT {
        *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;

        error!(method = ?request.method(), %remote_addr, "method not allows");

        return (response, None);
    }

    let host = match request.headers().get("host") {
        None => {
            error!("http connect host is empty");

            *response.status_mut() = StatusCode::BAD_REQUEST;

            return (response, None);
        }

        Some(host) => match host.to_str() {
            Err(err) => {
                error!(%err, "http connect host invalid");

                *response.status_mut() = StatusCode::BAD_REQUEST;

                return (response, None);
            }

            Ok(host) => host,
        },
    };

    let (target, port) = match host.rsplit_once(':') {
        None => {
            error!(host, "http connect host has no port");

            *response.status_mut() = StatusCode::BAD_REQUEST;

            return (response, None);
        }

        Some((target, port)) => {
            let port = match port.parse::<u16>() {
                Err(err) => {
                    error!(%err, "http connect host port invalid");

                    *response.status_mut() = StatusCode::BAD_REQUEST;

                    return (response, None);
                }

                Ok(port) => port,
            };

            (target.to_string(), port)
        }
    };

    (
        response,
        Some(DomainOrSocketAddr::Domain {
            domain: target,
            port,
        }),
    )
}

#[instrument(skip(request), err)]
async fn upgrade<B>(request: Request<B>, remote_addr: SocketAddr) -> io::Result<Upgraded> {
    upgrade::on(request).await.map_err(|err| {
        error!(%err, %remote_addr, "upgrade request failed");

        Error::new(ErrorKind::Other, err)
    })
}
