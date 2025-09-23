use libc::{c_void, size_t};
use std::sync::atomic::{AtomicPtr, AtomicU32, Ordering};
use tracing::{debug, error, info, warn};

use crate::ucx::{UcsStatus, UcsStatusPtr, UcpEpH, UcpRkeyH, UcpRequestParamT, ucs_status_to_ptr};
use crate::state::{DEBUG_ENABLED, IN_INTERCEPT, LOCAL_STATE};
use crate::shared_state::get_shared_state;
use crate::subscriber::get_current_state;

// function pointers to real UCX functions - use atomic pointer to avoid deadlock
static REAL_UCP_GET_NBX: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

pub fn try_find_real_ucp_get_nbx() -> *mut c_void {
    use std::ffi::CString;

    debug!("attempting to find real ucp_get_nbx function");

    // Try multiple approaches to find the real UCX function
    unsafe {
        let symbol_name = CString::new("ucp_get_nbx").unwrap();

        // First try RTLD_NEXT - this should work for library interposition
        info!("looking up symbol with RTLD_NEXT: ucp_get_nbx");
        let mut ptr = libc::dlsym(libc::RTLD_NEXT, symbol_name.as_ptr());

        // Check if we got our own function (infinite recursion trap)
        let our_function_addr = ucp_get_nbx as *const () as *mut c_void;
        info!("Our function address: {:?}, RTLD_NEXT returned: {:?}", our_function_addr, ptr);
        if ptr == our_function_addr {
            info!("RTLD_NEXT returned our own function, skipping");
            ptr = std::ptr::null_mut();
        }

        if ptr.is_null() {
            info!("RTLD_NEXT failed, trying RTLD_DEFAULT");
            ptr = libc::dlsym(libc::RTLD_DEFAULT, symbol_name.as_ptr());
            info!("RTLD_DEFAULT returned: {:?}", ptr);

            // Check again for our own function
            if ptr == our_function_addr {
                info!("RTLD_DEFAULT returned our own function, skipping");
                ptr = std::ptr::null_mut();
            }
        }

        if ptr.is_null() {
            info!("RTLD_DEFAULT failed, trying to find UCX libraries in loaded modules");

            // First, try to find where UCX is already loaded by reading memory maps
            let mut ucx_lib_paths = Vec::new();

            #[cfg(target_os = "linux")]
            {
                if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
                    for line in maps.lines() {
                        if line.contains("libucp") {
                            // Extract the library path from the maps line
                            if let Some(path_start) = line.rfind(' ') {
                                let path = &line[path_start + 1..];
                                if path.starts_with('/') && !ucx_lib_paths.contains(&path.to_string()) {
                                    ucx_lib_paths.push(path.to_string());
                                    info!("Found UCX library in memory map: {}", path);
                                }
                            }
                        }
                    }
                }
            }

            #[cfg(target_os = "macos")]
            {
                // On macOS, we can't easily read memory maps like on Linux
                // Instead, we'll rely on standard search paths
                info!("macOS detected, using standard UCX search paths");
            }

            // Add the found paths to our search list
            let mut ucx_lib_names = ucx_lib_paths;

            // Also try standard locations as fallback
            #[cfg(target_os = "linux")]
            ucx_lib_names.extend([
                "libucp.so".to_string(),
                "libucp.so.0".to_string(),
                "/usr/lib64/libucp.so".to_string(),
                "/usr/local/lib/libucp.so".to_string(),
                "/opt/ucx/lib/libucp.so".to_string(),
            ]);

            #[cfg(target_os = "macos")]
            {
                let home = std::env::var("HOME").unwrap_or_default();
                ucx_lib_names.extend([
                    "libucp.dylib".to_string(),
                    "libucp.0.dylib".to_string(),
                    "/usr/local/lib/libucp.dylib".to_string(),
                    "/opt/homebrew/lib/libucp.dylib".to_string(),
                    format!("{}/ucx/lib/libucp.dylib", home),
                ]);
            }

            for lib_name in &ucx_lib_names {
                info!("Trying to load library: {}", lib_name);
                let lib_name_c = CString::new(lib_name.as_str()).unwrap();
                let handle = libc::dlopen(lib_name_c.as_ptr(), libc::RTLD_LAZY);
                if !handle.is_null() {
                    info!(lib_name, "successfully loaded library");
                    ptr = libc::dlsym(handle, symbol_name.as_ptr());
                    if !ptr.is_null() {
                        info!(lib_name, address = ?ptr, "found ucp_get_nbx");
                        break;
                    } else {
                        info!(lib_name, "library loaded but ucp_get_nbx not found");
                    }
                } else {
                    let error = libc::dlerror();
                    let error_str = if !error.is_null() {
                        std::ffi::CStr::from_ptr(error).to_string_lossy()
                    } else {
                        "unknown error".into()
                    };
                    info!(lib_name, error = %error_str, "failed to load library");
                }
            }
        }

        if ptr.is_null() {
            debug!("failed to find ucp_get_nbx symbol via any method");
            let error = libc::dlerror();
            if !error.is_null() {
                let error_str = std::ffi::CStr::from_ptr(error);
                debug!(error = ?error_str, "dlsym error");
            }
        } else {
            debug!(address = ?ptr, "successfully found ucp_get_nbx");
        }

        ptr
    }
}

pub fn init_real_ucp_get_nbx() {
    let ptr = try_find_real_ucp_get_nbx();
    REAL_UCP_GET_NBX.store(ptr, Ordering::Relaxed);
    debug!(ptr_loaded = !ptr.is_null(), "real UCX function pointer stored during init");
}

// helper function to decide fault injection using local state
pub fn should_inject_fault() -> Option<UcsStatus> {
    let enabled = LOCAL_STATE.enabled.load(Ordering::Relaxed);

    if !enabled {
        return None;
    }

    let mut strategy = LOCAL_STATE.strategy.lock().unwrap();
    strategy.should_inject()
}

// UCX function interceptors - focused on ucp_get_nbx for remote reads
#[no_mangle]
pub extern "C" fn ucp_get_nbx(
    ep: UcpEpH,
    buffer: *mut c_void,
    count: size_t,
    remote_addr: u64,
    rkey: UcpRkeyH,
    param: UcpRequestParamT,
) -> UcsStatusPtr {
    // Check reentrancy guard to prevent infinite recursion
    let already_in_intercept = IN_INTERCEPT.with(|flag| {
        *flag.borrow()
    });

    if already_in_intercept {
        // We're being called recursively - this shouldn't happen if we resolve correctly
        // but as a safety fallback, return success to avoid infinite recursion
        warn!("RECURSION DETECTED: ucp_get_nbx called while already intercepting");
        return std::ptr::null_mut(); // UCS_OK
    }

    // Set reentrancy guard
    IN_INTERCEPT.with(|flag| {
        *flag.borrow_mut() = true;
    });

    // Update shared statistics (zero-overhead atomic increments)
    if let Some(shared) = get_shared_state() {
        shared.total_calls.fetch_add(1, Ordering::Relaxed);
        shared.ucp_get_nbx_calls.fetch_add(1, Ordering::Relaxed);
    }

    // Always log the first few calls to verify hook is working
    static CALL_COUNT: AtomicU32 = AtomicU32::new(0);
    let call_num = CALL_COUNT.fetch_add(1, Ordering::Relaxed);

    if DEBUG_ENABLED.load(Ordering::Relaxed) || call_num < 5 {
        info!(
            "ucp_get_nbx called #{} - ep: {:?}, buffer: {:?}, count: {}, remote_addr: 0x{:x}, rkey: {:?}, param: {:?}",
            call_num, ep, buffer, count, remote_addr, rkey, param
        );

        let state = get_current_state();
        info!(
            "Fault state: enabled={}, strategy={}, pattern={:?}, error_codes={:?}",
            state.enabled, state.strategy, state.pattern, state.error_codes
        );
    }

    if let Some(error_code) = should_inject_fault() {
        // Update fault statistics in shared memory
        if let Some(shared) = get_shared_state() {
            shared.faults_injected.fetch_add(1, Ordering::Relaxed);
            shared.ucp_get_nbx_faults.fetch_add(1, Ordering::Relaxed);
            shared.calls_since_fault.store(0, Ordering::Relaxed);
        }

        warn!(error_code = error_code, "[FAULT] INJECTED: ucp_get_nbx error ({})", error_code);
        let fault_result = ucs_status_to_ptr(error_code);

        // Clear reentrancy guard before returning fault result
        IN_INTERCEPT.with(|flag| {
            *flag.borrow_mut() = false;
        });
        return fault_result;
    } else {
        // No fault injected, increment calls since last fault
        if let Some(shared) = get_shared_state() {
            shared.calls_since_fault.fetch_add(1, Ordering::Relaxed);
        }
    }

    // Get the real function pointer atomically - with lazy initialization
    let mut real_fn_ptr = REAL_UCP_GET_NBX.load(Ordering::Relaxed);

    // If not initialized yet, try to initialize it now
    if real_fn_ptr.is_null() {
        real_fn_ptr = try_find_real_ucp_get_nbx();
        if !real_fn_ptr.is_null() {
            REAL_UCP_GET_NBX.store(real_fn_ptr, Ordering::Relaxed);
            debug!(address = ?real_fn_ptr, "lazy initialized real ucp_get_nbx function");
        }
    }

    let result = if !real_fn_ptr.is_null() {
        // Cast to function pointer and call
        let real_fn: extern "C" fn(UcpEpH, *mut c_void, size_t, u64, UcpRkeyH, UcpRequestParamT) -> UcsStatusPtr =
            unsafe { std::mem::transmute(real_fn_ptr) };

        info!(call_num, address = ?real_fn_ptr, "calling real ucp_get_nbx function");
        let result = real_fn(ep, buffer, count, remote_addr, rkey, param);
        info!(call_num, result = ?result, result_int = result as isize, "real ucp_get_nbx returned");

        // Skip buffer access for now to avoid segfault - UCX operations are async
        result
    } else {
        // Can't find real function - return error since we can't perform the operation
        error!(call_num, "real ucp_get_nbx not found, returning IO_ERROR since operation cannot be completed");
        ucs_status_to_ptr(crate::ucx::UCS_ERR_IO_ERROR) // Return error instead of fake success
    };

    // Clear reentrancy guard before returning
    IN_INTERCEPT.with(|flag| {
        *flag.borrow_mut() = false;
    });

    result
}