use std::env;
use std::path::PathBuf;

use bindgen::EnumVariation;

fn main() {
    println!("cargo:rerun-if-changed=require.h");

    generate_require();
}

fn generate_require() {
    let bindings = bindgen::builder()
        .use_core()
        .ctypes_prefix("::aya_ebpf::cty")
        .layout_tests(false)
        .generate_comments(false)
        .clang_arg("-Wno-unknown-attributes")
        .default_enum_style(EnumVariation::ModuleConsts)
        .prepend_enum_name(false)
        .derive_debug(false)
        .header("require.h")
        .allowlist_type(".*")
        .allowlist_var(".*")
        .size_t_is_usize(false)
        .generate()
        .unwrap();

    let path = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("require.rs");

    bindings.write_to_file(path).unwrap();
}
