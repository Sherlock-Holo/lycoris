use std::io;
use std::io::ErrorKind;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use bytes::Bytes;
use futures_channel::mpsc::Sender;
use futures_util::{Sink, SinkExt, Stream};
use http::HeaderMap;
use hyper::body::{Body, Frame, Incoming};

#[derive(Debug)]
pub struct BodyStream {
    body: Incoming,
}

impl From<Incoming> for BodyStream {
    fn from(value: Incoming) -> Self {
        Self { body: value }
    }
}

impl Stream for BodyStream {
    type Item = io::Result<Bytes>;

    #[inline]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let result = Pin::new(&mut self.body)
            .poll_frame(cx)
            .map_err(|err| io::Error::new(ErrorKind::Other, err))?;
        match ready!(result) {
            None => Poll::Ready(None),
            Some(frame) => match frame.into_data() {
                Err(_) => Poll::Ready(None),
                Ok(data) => Poll::Ready(Some(Ok(data))),
            },
        }
    }
}

#[derive(Debug)]
pub struct SinkBodySender<E> {
    sender: Sender<Result<Frame<Bytes>, E>>,
    is_trailer_sent: bool,
}

impl<E> From<Sender<Result<Frame<Bytes>, E>>> for SinkBodySender<E> {
    fn from(value: Sender<Result<Frame<Bytes>, E>>) -> Self {
        Self {
            sender: value,
            is_trailer_sent: false,
        }
    }
}

impl<'a, E> Sink<&'a [u8]> for SinkBodySender<E> {
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
            .start_send_unpin(Ok(Frame::data(Bytes::copy_from_slice(item))))
            .map_err(|err| io::Error::new(ErrorKind::Other, err))
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.sender
            .poll_flush_unpin(cx)
            .map_err(|err| io::Error::new(ErrorKind::Other, err))
    }

    #[inline]
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if !self.is_trailer_sent {
            ready!(self.as_mut().poll_ready(cx))?;

            self.sender
                .start_send_unpin(Ok(Frame::trailers(HeaderMap::new())))
                .map_err(|_| io::Error::from(ErrorKind::BrokenPipe))?;

            self.is_trailer_sent = true;
        }

        self.sender
            .poll_close_unpin(cx)
            .map_err(|err| io::Error::new(ErrorKind::Other, err))
    }
}
