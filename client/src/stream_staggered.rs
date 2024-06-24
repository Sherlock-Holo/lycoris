use core::async_iter::AsyncIterator;
use core::future::poll_fn;
use core::pin::{pin, Pin};

use futures_util::future::Either;
use futures_util::{Stream, StreamExt};

pub trait StreamStaggered: Stream {
    fn staggered<S: Stream<Item = Self::Item>>(self, s2: S) -> impl AsyncIterator<Item = Self::Item>
    where
        Self: Sized,
    {
        staggered(self, s2)
    }
}

impl<T: Stream> StreamStaggered for T {}

async gen fn staggered<S1, S2>(s1: S1, s2: S2) -> S1::Item
where
    S1: Stream,
    S2: Stream<Item = S1::Item>,
{
    let mut s1 = pin!(s1);
    let mut s2 = pin!(s2);
    let mut last;

    loop {
        match s1.next().await {
            Some(item) => yield item,
            None => {
                last = Either::Right(s2);

                break;
            }
        }

        match s2.next().await {
            Some(item) => yield item,
            None => {
                last = Either::Left(s1);

                break;
            }
        }
    }

    while let Some(item) = last.next().await {
        yield item;
    }
}

pub trait AsyncIteratorExt: AsyncIterator {
    async fn next(&mut self) -> Option<Self::Item>
    where
        Self: Unpin,
    {
        let mut this = Pin::new(self);
        poll_fn(|cx| this.as_mut().poll_next(cx)).await
    }
}

impl<T: AsyncIterator> AsyncIteratorExt for T {}

#[cfg(test)]
mod tests {
    use futures_util::stream;

    use super::*;

    #[tokio::test]
    async fn staggered() {
        let new_stream = stream::iter([1, 2, 3]).staggered(stream::iter([4, 5, 6]));
        let mut new_stream = pin!(new_stream);

        assert_eq!(new_stream.next().await, Some(1));
        assert_eq!(new_stream.next().await, Some(4));
        assert_eq!(new_stream.next().await, Some(2));
        assert_eq!(new_stream.next().await, Some(5));
        assert_eq!(new_stream.next().await, Some(3));
        assert_eq!(new_stream.next().await, Some(6));
        assert_eq!(new_stream.next().await, None);
    }

    #[tokio::test]
    async fn staggered_not_algned() {
        let new_stream = stream::iter([1, 2, 3]).staggered(stream::iter([4, 5]));
        let mut new_stream = pin!(new_stream);

        assert_eq!(new_stream.next().await, Some(1));
        assert_eq!(new_stream.next().await, Some(4));
        assert_eq!(new_stream.next().await, Some(2));
        assert_eq!(new_stream.next().await, Some(5));
        assert_eq!(new_stream.next().await, Some(3));
        assert_eq!(new_stream.next().await, None);
    }
}
