use std::env;
use std::path::PathBuf;

fn main() {
    let home = env::var("HOME").expect("HOME environment variable not set");
    let ucx_prefix = PathBuf::from(home).join("ucx");

    // Set UCX paths
    let ucx_include = ucx_prefix.join("include");
    let ucx_lib = ucx_prefix.join("lib");

    // Tell cargo about the library paths
    println!("cargo:rustc-link-search=native={}", ucx_lib.display());

    // Try pkg-config first, fallback to manual paths
    if pkg_config::Config::new().probe("ucx").is_err() {
        eprintln!("pkg-config failed, using manual UCX paths: {}", ucx_prefix.display());
        println!("cargo:rustc-link-lib=ucp");
        println!("cargo:rustc-link-lib=ucs");
        println!("cargo:rustc-link-lib=uct");
    }

    // Generate bindings for UCX headers
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg(format!("-I{}", ucx_include.display()))
        // Include UCP functions we want to intercept - focusing on ucp_get_nbx
        .allowlist_function("ucp_get_nbx")
        // Include relevant UCX types for ucp_get_nbx
        .allowlist_type("ucs_status_t")
        .allowlist_type("ucs_status_ptr_t")
        .allowlist_type("ucp_ep_h")
        .allowlist_type("ucp_rkey_h")
        .allowlist_type("ucp_request_param_t")
        // Include UCX constants
        .allowlist_var("UCS_OK")
        .allowlist_var("UCS_ERR_.*")
        // Generate proper Rust types
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate UCX bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    println!("cargo:rustc-link-lib=ucp");
    println!("cargo:rustc-link-lib=ucs");
    println!("cargo:rustc-link-lib=uct");
}