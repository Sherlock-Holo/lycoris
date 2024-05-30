use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use event_listener::{Event, EventListener};
use futures_util::FutureExt;
use pin_project::pin_project;
use thiserror::Error;

#[derive(Debug, Default, Clone)]
pub struct AbortHandle {
    event: Arc<Event>,
}

impl AbortHandle {
    pub fn abort(&self) {
        self.event.notify(usize::MAX);
    }
}

#[derive(Debug, Error, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
#[error("Future is aborted")]
pub struct Aborted;

#[pin_project]
pub struct Abortable<F> {
    #[pin]
    fut: F,
    event_listener: EventListener,
}

impl<F: Future> Future for Abortable<F> {
    type Output = Result<F::Output, Aborted>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this.fut.poll(cx) {
            Poll::Pending => this.event_listener.poll_unpin(cx).map(|_| Err(Aborted)),
            Poll::Ready(res) => Poll::Ready(Ok(res)),
        }
    }
}

pub trait FutureAbortExt {
    fn abortable(self, abort_handle: &AbortHandle) -> Abortable<Self>
    where
        Self: Sized,
    {
        Abortable {
            fut: self,
            event_listener: abort_handle.event.listen(),
        }
    }
}

impl<T> FutureAbortExt for T {}

#[cfg(test)]
mod tests {
    use std::future::{pending, ready};

    use super::*;

    #[test]
    fn ready_before_abort() {
        futures_executor::block_on(async {
            let abort_handle = AbortHandle::default();
            let fut1 = ready(1).abortable(&abort_handle);
            let fut2 = ready(2).abortable(&abort_handle);
            abort_handle.abort();

            assert_eq!(fut1.await.unwrap(), 1);
            assert_eq!(fut2.await.unwrap(), 2);
        })
    }

    #[test]
    fn abort_before_ready() {
        futures_executor::block_on(async {
            let abort_handle = AbortHandle::default();
            let fut1 = pending::<()>().abortable(&abort_handle);
            let fut2 = pending::<()>().abortable(&abort_handle);
            abort_handle.abort();

            assert_eq!(fut1.await.unwrap_err(), Aborted);
            assert_eq!(fut2.await.unwrap_err(), Aborted);
        })
    }

    #[test]
    fn abort_and_ready() {
        futures_executor::block_on(async {
            let abort_handle = AbortHandle::default();
            let fut1 = ready(1).abortable(&abort_handle);
            let fut2 = pending::<()>().abortable(&abort_handle);
            abort_handle.abort();

            assert_eq!(fut1.await.unwrap(), 1);
            assert_eq!(fut2.await.unwrap_err(), Aborted);
        })
    }
}
