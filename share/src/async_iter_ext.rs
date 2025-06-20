use core::async_iter::AsyncIterator;
use core::future::poll_fn;
use core::pin::{Pin, pin};

#[allow(async_fn_in_trait)]
pub trait AsyncIteratorExt: AsyncIterator {
    async fn next(&mut self) -> Option<Self::Item>
    where
        Self: Unpin,
    {
        let mut this = Pin::new(self);
        poll_fn(|cx| this.as_mut().poll_next(cx)).await
    }

    async gen fn enumerate(self) -> (usize, Self::Item)
    where
        Self: Sized,
    {
        let mut this = pin!(self);
        let mut idx = 0;
        while let Some(item) = this.next().await {
            yield (idx, item);
            idx += 1;
        }
    }
}

impl<T: AsyncIterator> AsyncIteratorExt for T {}
