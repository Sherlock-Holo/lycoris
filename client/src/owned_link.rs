use std::ops::{Deref, DerefMut};

use aya::programs::Link;

pub struct OwnedLink<T: Link> {
    link: Option<T>,
}

impl<T: Link> From<T> for OwnedLink<T> {
    fn from(link: T) -> Self {
        Self { link: Some(link) }
    }
}

impl<T: Link> Deref for OwnedLink<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.link.as_ref().unwrap()
    }
}

impl<T: Link> DerefMut for OwnedLink<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.link.as_mut().unwrap()
    }
}

impl<T: Link> Drop for OwnedLink<T> {
    fn drop(&mut self) {
        let _ = self.link.take().unwrap().detach();
    }
}
