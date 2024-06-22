pub trait ArrayExt {
    /// swap every element bytes
    fn swap_bytes(self) -> Self;
}

macro_rules! array_ext {
    ($t:ty) => {
        impl<const N: usize> ArrayExt for [$t; N] {
            fn swap_bytes(mut self) -> Self {
                for v in self.iter_mut() {
                    *v = v.swap_bytes();
                }

                self
            }
        }
    };
}

array_ext!(u8);
array_ext!(u16);
