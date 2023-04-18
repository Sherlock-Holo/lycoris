use std::future::Future;
use std::io;
use std::io::ErrorKind;
use std::pin::{pin, Pin};
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::{Sink, Stream, StreamExt};
use http::HeaderMap;
use hyper::body::Sender;
use hyper::Body;

#[derive(Debug)]
pub struct BodyStream {
    body: Body,
}

impl BodyStream {
    pub fn new(body: Body) -> Self {
        Self { body }
    }
}

impl Stream for BodyStream {
    type Item = io::Result<Bytes>;

    #[inline]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.body
            .poll_next_unpin(cx)
            .map_err(|err| io::Error::new(ErrorKind::Other, err))
    }
}

#[derive(Debug)]
pub struct SinkBodySender {
    sender: Sender,
}

impl SinkBodySender {
    pub fn new(sender: Sender) -> Self {
        Self { sender }
    }
}

impl<'a> Sink<&'a [u8]> for SinkBodySender {
    type Error = io::Error;

    #[inline]
    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.sender
            .poll_ready(cx)
            .map_err(|err| io::Error::new(ErrorKind::Other, err))
    }

    #[inline]
    fn start_send(mut self: Pin<&mut Self>, item: &'a [u8]) -> Result<(), Self::Error> {
        self.sender
            .try_send_data(Bytes::copy_from_slice(item))
            .map_err(|_| io::Error::new(ErrorKind::Other, "sender not ready"))
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    #[inline]
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // this async fn actually is a normal fn
        let fut = self.sender.send_trailers(HeaderMap::new());
        let fut = pin!(fut);

        fut.poll(cx)
            .map_err(|err| io::Error::new(ErrorKind::Other, err))
    }
}
