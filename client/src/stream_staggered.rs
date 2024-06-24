use core::pin::pin;

use futures_util::future::Either;
use futures_util::{Stream, StreamExt};

pub trait StreamStaggered: Stream {
    async gen fn staggered<S: Stream<Item = Self::Item>>(self, s2: S) -> Self::Item
    where
        Self: Sized,
    {
        let mut s1 = pin!(self);
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
}

impl<T: Stream> StreamStaggered for T {}

#[cfg(test)]
mod tests {
    use futures_util::stream;

    use super::*;
    use crate::async_iter_ext::AsyncIteratorExt;

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
