macro_rules! name_it {
    ($name:ident) => {
        pub const $name: &str = stringify!($name);
    };
}

name_it!(DST_IPV4_ADDR_STORE);
name_it!(IPV4_ADDR_MAP);
name_it!(PROXY_IPV4_LIST);
name_it!(PROXY_IPV4_LIST_MODE);
name_it!(PROXY_IPV4_CLIENT);
