use std::env;
use std::path::PathBuf;

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    // Check if UCX is available
    let ucx_available = if target_os == "macos" {
        // For macOS, check if UCX was successfully built
        let home = env::var("HOME").expect("HOME environment variable not set");
        let ucx_lib = PathBuf::from(home).join("ucx").join("lib");
        ucx_lib.exists() && ucx_lib.join("libucp.dylib").exists()
    } else {
        // For Linux, try pkg-config first
        pkg_config::Config::new().probe("ucx").is_ok()
    };

    if ucx_available {
        println!("cargo:rustc-cfg=ucx_available");

        let home = env::var("HOME").expect("HOME environment variable not set");
        let ucx_prefix = PathBuf::from(home).join("ucx");
        let ucx_include = ucx_prefix.join("include");
        let ucx_lib = ucx_prefix.join("lib");

        // Tell cargo about the library paths
        println!("cargo:rustc-link-search=native={}", ucx_lib.display());

        // Try pkg-config first, fallback to manual paths
        if pkg_config::Config::new().probe("ucx").is_err() {
            eprintln!(
                "pkg-config failed, using manual UCX paths: {}",
                ucx_prefix.display()
            );
            if target_os == "macos" {
                println!("cargo:rustc-link-lib=dylib=ucp");
                println!("cargo:rustc-link-lib=dylib=ucs");
                println!("cargo:rustc-link-lib=dylib=uct");
            } else {
                println!("cargo:rustc-link-lib=ucp");
                println!("cargo:rustc-link-lib=ucs");
                println!("cargo:rustc-link-lib=uct");
            }
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
    } else {
        println!("cargo:rustc-cfg=ucx_stub");
        eprintln!("UCX not available, building with stub implementation");

        // Generate minimal stub bindings from wrapper.h without UCX
        let bindings = bindgen::Builder::default()
            .header("wrapper.h")
            // Include basic types we define in wrapper.h
            .allowlist_type("ucs_status_t")
            .allowlist_type("ucs_status_ptr_t")
            .allowlist_type("ucp_ep_h")
            .allowlist_type("ucp_rkey_h")
            .allowlist_type("ucp_request_param_t")
            // Include UCX constants we define
            .allowlist_var("UCS_OK")
            .allowlist_var("UCS_ERR_.*")
            // Allow the stub function
            .allowlist_function("ucp_get_nbx")
            // Generate proper Rust types
            .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
            .generate()
            .expect("Unable to generate stub UCX bindings");

        let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
        bindings
            .write_to_file(out_path.join("bindings.rs"))
            .expect("Couldn't write stub bindings!");
    }
}
