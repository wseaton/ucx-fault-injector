//! generic symbol lookup to avoid duplication across UCX function finders

use libc::c_void;
use std::ffi::CString;
use tracing::debug;

/// generic function to find real UCX symbols, avoiding our own function addresses
pub fn find_real_ucx_function(symbol_name: &str, our_function_addr: *mut c_void) -> *mut c_void {
    debug!(
        pid = std::process::id(),
        "attempting to find real {} function", symbol_name
    );

    unsafe {
        let symbol_cstr = CString::new(symbol_name).unwrap();

        // first try RTLD_NEXT - this should work for library interposition
        debug!(
            pid = std::process::id(),
            "looking up symbol with RTLD_NEXT: {}", symbol_name
        );
        let mut ptr = libc::dlsym(libc::RTLD_NEXT, symbol_cstr.as_ptr());

        // check if we got our own function (infinite recursion trap)
        debug!(
            pid = std::process::id(),
            "our function address: {:?}, RTLD_NEXT returned: {:?}", our_function_addr, ptr
        );
        if ptr == our_function_addr {
            debug!(
                pid = std::process::id(),
                "RTLD_NEXT returned our own function, skipping"
            );
            ptr = std::ptr::null_mut();
        }

        // try RTLD_DEFAULT if RTLD_NEXT failed
        if ptr.is_null() {
            debug!(
                pid = std::process::id(),
                "RTLD_NEXT failed, trying RTLD_DEFAULT"
            );
            ptr = libc::dlsym(libc::RTLD_DEFAULT, symbol_cstr.as_ptr());
            debug!(pid = std::process::id(), "RTLD_DEFAULT returned: {:?}", ptr);

            // check again for our own function
            if ptr == our_function_addr {
                debug!(
                    pid = std::process::id(),
                    "RTLD_DEFAULT returned our own function, skipping"
                );
                ptr = std::ptr::null_mut();
            }
        }

        // search memory maps for UCX libraries
        if ptr.is_null() {
            debug!(
                pid = std::process::id(),
                "RTLD_DEFAULT failed, trying to find UCX libraries in loaded modules"
            );

            ptr = search_memory_maps_for_symbol(&symbol_cstr, our_function_addr);
        }

        // final attempt - try common UCX library names
        if ptr.is_null() {
            ptr = search_common_libraries_for_symbol(&symbol_cstr, our_function_addr);
        }

        debug!(
            pid = std::process::id(),
            address = ?ptr,
            symbol_found = !ptr.is_null(),
            "{} symbol lookup completed", symbol_name
        );
        ptr
    }
}

/// search /proc/self/maps for UCX libraries (linux only)
#[cfg(target_os = "linux")]
fn search_memory_maps_for_symbol(
    symbol_cstr: &CString,
    our_function_addr: *mut c_void,
) -> *mut c_void {
    let ucx_lib_paths = find_ucx_libraries_in_maps();

    unsafe {
        for lib_path in ucx_lib_paths {
            let lib_path_cstr = CString::new(lib_path.as_str()).unwrap();
            let handle = libc::dlopen(lib_path_cstr.as_ptr(), libc::RTLD_LAZY | libc::RTLD_NOLOAD);
            if !handle.is_null() {
                let ptr = libc::dlsym(handle, symbol_cstr.as_ptr());
                if !ptr.is_null() && ptr != our_function_addr {
                    debug!(
                        pid = std::process::id(),
                        "found symbol in {}: {:?}", lib_path, ptr
                    );
                    return ptr;
                }
                // note: don't call dlclose since RTLD_NOLOAD just gets a reference
            }
        }
    }
    std::ptr::null_mut()
}

#[cfg(target_os = "linux")]
fn find_ucx_libraries_in_maps() -> Vec<String> {
    let mut paths = Vec::new();
    if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
        for line in maps.lines() {
            if line.contains("libucp") {
                // extract the library path from the maps line
                if let Some(path_start) = line.rfind(' ') {
                    let path = &line[path_start + 1..];
                    if path.starts_with('/') && !paths.contains(&path.to_string()) {
                        paths.push(path.to_string());
                        debug!(
                            pid = std::process::id(),
                            "found UCX library in memory map: {}", path
                        );
                    }
                }
            }
        }
    }
    paths
}

#[cfg(not(target_os = "linux"))]
fn search_memory_maps_for_symbol(
    _symbol_cstr: &CString,
    _our_function_addr: *mut c_void,
) -> *mut c_void {
    std::ptr::null_mut()
}

/// try common UCX library names as a last resort
fn search_common_libraries_for_symbol(
    symbol_cstr: &CString,
    our_function_addr: *mut c_void,
) -> *mut c_void {
    let common_ucx_libs = ["libucp.so.0", "libucp.so", "libucp.dylib"];

    unsafe {
        for lib_name in &common_ucx_libs {
            let lib_name_cstr = CString::new(*lib_name).unwrap();
            let handle = libc::dlopen(lib_name_cstr.as_ptr(), libc::RTLD_LAZY | libc::RTLD_NOLOAD);
            if !handle.is_null() {
                let ptr = libc::dlsym(handle, symbol_cstr.as_ptr());
                if !ptr.is_null() && ptr != our_function_addr {
                    debug!(
                        pid = std::process::id(),
                        "found symbol in {}: {:?}", lib_name, ptr
                    );
                    return ptr;
                }
            }
        }
    }
    std::ptr::null_mut()
}
