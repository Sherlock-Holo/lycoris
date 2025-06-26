pub mod require {
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]
    #![allow(non_snake_case)]
    #![allow(unused_unsafe)]
    #![allow(clippy::all)]
    #![allow(unused)]
    #![allow(unsafe_op_in_unsafe_fn)]

    include!(concat!(env!("OUT_DIR"), "/require.rs"));
}
