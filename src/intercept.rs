use libc::{c_void, size_t};
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, Ordering};
use tracing::{debug, error, trace, warn};

use crate::recorder::{CallParams, FunctionType};
use crate::state::{is_in_intercept, set_in_intercept, DEBUG_ENABLED, LOCAL_STATE};
use crate::subscriber::get_current_state;
use crate::ucx::{ucs_status_to_ptr, UcpEpH, UcpRequestParamT, UcpRkeyH, UcsStatus, UcsStatusPtr};

// function pointers to real UCX functions - use atomic pointer to avoid deadlock
static REAL_UCP_GET_NBX: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_UCP_PUT_NBX: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_UCP_EP_FLUSH_NBX: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

pub fn try_find_real_ucp_get_nbx() -> *mut c_void {
    use std::ffi::CString;

    debug!(
        pid = std::process::id(),
        "attempting to find real ucp_get_nbx function"
    );

    // Try multiple approaches to find the real UCX function
    unsafe {
        let symbol_name = CString::new("ucp_get_nbx").unwrap();

        // First try RTLD_NEXT - this should work for library interposition
        debug!(
            pid = std::process::id(),
            "looking up symbol with RTLD_NEXT: ucp_get_nbx"
        );
        let mut ptr = libc::dlsym(libc::RTLD_NEXT, symbol_name.as_ptr());

        // Check if we got our own function (infinite recursion trap)
        let our_function_addr = ucp_get_nbx as *const () as *mut c_void;
        debug!(
            pid = std::process::id(),
            "Our function address: {:?}, RTLD_NEXT returned: {:?}", our_function_addr, ptr
        );
        if ptr == our_function_addr {
            debug!(
                pid = std::process::id(),
                "RTLD_NEXT returned our own function, skipping"
            );
            ptr = std::ptr::null_mut();
        }

        if ptr.is_null() {
            debug!(
                pid = std::process::id(),
                "RTLD_NEXT failed, trying RTLD_DEFAULT"
            );
            ptr = libc::dlsym(libc::RTLD_DEFAULT, symbol_name.as_ptr());
            debug!(pid = std::process::id(), "RTLD_DEFAULT returned: {:?}", ptr);

            // Check again for our own function
            if ptr == our_function_addr {
                debug!(
                    pid = std::process::id(),
                    "RTLD_DEFAULT returned our own function, skipping"
                );
                ptr = std::ptr::null_mut();
            }
        }

        if ptr.is_null() {
            debug!(
                pid = std::process::id(),
                "RTLD_DEFAULT failed, trying to find UCX libraries in loaded modules"
            );

            // First, try to find where UCX is already loaded by reading memory maps
            #[cfg(target_os = "linux")]
            let ucx_lib_paths = {
                let mut paths = Vec::new();
                if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
                    for line in maps.lines() {
                        if line.contains("libucp") {
                            // Extract the library path from the maps line
                            if let Some(path_start) = line.rfind(' ') {
                                let path = &line[path_start + 1..];
                                if path.starts_with('/') && !paths.contains(&path.to_string()) {
                                    paths.push(path.to_string());
                                    debug!(
                                        pid = std::process::id(),
                                        "Found UCX library in memory map: {}", path
                                    );
                                }
                            }
                        }
                    }
                }
                paths
            };

            #[cfg(not(target_os = "linux"))]
            let ucx_lib_paths: Vec<String> = Vec::new();

            // Try to dlopen each found UCX library and look for the symbol
            for lib_path in ucx_lib_paths {
                let lib_path_cstr = CString::new(lib_path.as_str()).unwrap();
                let handle =
                    libc::dlopen(lib_path_cstr.as_ptr(), libc::RTLD_LAZY | libc::RTLD_NOLOAD);
                if !handle.is_null() {
                    ptr = libc::dlsym(handle, symbol_name.as_ptr());
                    if !ptr.is_null() && ptr != our_function_addr {
                        debug!(
                            pid = std::process::id(),
                            "Found ucp_get_nbx in {}: {:?}", lib_path, ptr
                        );
                        break;
                    }
                    // Note: don't call dlclose since RTLD_NOLOAD just gets a reference
                }
            }
        }

        if ptr.is_null() {
            // Final attempt - try some common UCX library names
            let common_ucx_libs = ["libucp.so.0", "libucp.so", "libucp.dylib"];
            for lib_name in &common_ucx_libs {
                let lib_name_cstr = CString::new(*lib_name).unwrap();
                let handle =
                    libc::dlopen(lib_name_cstr.as_ptr(), libc::RTLD_LAZY | libc::RTLD_NOLOAD);
                if !handle.is_null() {
                    ptr = libc::dlsym(handle, symbol_name.as_ptr());
                    if !ptr.is_null() && ptr != our_function_addr {
                        debug!(
                            pid = std::process::id(),
                            "Found ucp_get_nbx in {}: {:?}", lib_name, ptr
                        );
                        break;
                    }
                }
            }
        }

        debug!(pid = std::process::id(), address = ?ptr, symbol_found = !ptr.is_null(), "ucp_get_nbx symbol lookup completed");
        ptr
    }
}

pub fn try_find_real_ucp_put_nbx() -> *mut c_void {
    use std::ffi::CString;

    debug!(
        pid = std::process::id(),
        "attempting to find real ucp_put_nbx function"
    );

    // Try multiple approaches to find the real UCX function
    unsafe {
        let symbol_name = CString::new("ucp_put_nbx").unwrap();

        // First try RTLD_NEXT - this should work for library interposition
        debug!(
            pid = std::process::id(),
            "looking up symbol with RTLD_NEXT: ucp_put_nbx"
        );
        let mut ptr = libc::dlsym(libc::RTLD_NEXT, symbol_name.as_ptr());

        // Check if we got our own function (infinite recursion trap)
        let our_function_addr = ucp_put_nbx as *const () as *mut c_void;
        debug!(
            pid = std::process::id(),
            "Our function address: {:?}, RTLD_NEXT returned: {:?}", our_function_addr, ptr
        );
        if ptr == our_function_addr {
            debug!(
                pid = std::process::id(),
                "RTLD_NEXT returned our own function, skipping"
            );
            ptr = std::ptr::null_mut();
        }

        if ptr.is_null() {
            debug!(
                pid = std::process::id(),
                "RTLD_NEXT failed, trying RTLD_DEFAULT"
            );
            ptr = libc::dlsym(libc::RTLD_DEFAULT, symbol_name.as_ptr());
            debug!(pid = std::process::id(), "RTLD_DEFAULT returned: {:?}", ptr);

            // Check again for our own function
            if ptr == our_function_addr {
                debug!(
                    pid = std::process::id(),
                    "RTLD_DEFAULT returned our own function, skipping"
                );
                ptr = std::ptr::null_mut();
            }
        }

        if ptr.is_null() {
            debug!(
                pid = std::process::id(),
                "RTLD_DEFAULT failed, trying to find UCX libraries in loaded modules"
            );

            // First, try to find where UCX is already loaded by reading memory maps
            #[cfg(target_os = "linux")]
            let ucx_lib_paths = {
                let mut paths = Vec::new();
                if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
                    for line in maps.lines() {
                        if line.contains("libucp") {
                            // Extract the library path from the maps line
                            if let Some(path_start) = line.rfind(' ') {
                                let path = &line[path_start + 1..];
                                if path.starts_with('/') && !paths.contains(&path.to_string()) {
                                    paths.push(path.to_string());
                                    debug!(
                                        pid = std::process::id(),
                                        "Found UCX library in memory map: {}", path
                                    );
                                }
                            }
                        }
                    }
                }
                paths
            };

            #[cfg(not(target_os = "linux"))]
            let ucx_lib_paths: Vec<String> = Vec::new();

            // Try to dlopen each found UCX library and look for the symbol
            for lib_path in ucx_lib_paths {
                let lib_path_cstr = CString::new(lib_path.as_str()).unwrap();
                let handle =
                    libc::dlopen(lib_path_cstr.as_ptr(), libc::RTLD_LAZY | libc::RTLD_NOLOAD);
                if !handle.is_null() {
                    ptr = libc::dlsym(handle, symbol_name.as_ptr());
                    if !ptr.is_null() && ptr != our_function_addr {
                        debug!(
                            pid = std::process::id(),
                            "Found ucp_put_nbx in {}: {:?}", lib_path, ptr
                        );
                        break;
                    }
                    // Note: don't call dlclose since RTLD_NOLOAD just gets a reference
                }
            }
        }

        if ptr.is_null() {
            // Final attempt - try some common UCX library names
            let common_ucx_libs = ["libucp.so.0", "libucp.so", "libucp.dylib"];
            for lib_name in &common_ucx_libs {
                let lib_name_cstr = CString::new(*lib_name).unwrap();
                let handle =
                    libc::dlopen(lib_name_cstr.as_ptr(), libc::RTLD_LAZY | libc::RTLD_NOLOAD);
                if !handle.is_null() {
                    ptr = libc::dlsym(handle, symbol_name.as_ptr());
                    if !ptr.is_null() && ptr != our_function_addr {
                        debug!(
                            pid = std::process::id(),
                            "Found ucp_put_nbx in {}: {:?}", lib_name, ptr
                        );
                        break;
                    }
                }
            }
        }

        debug!(pid = std::process::id(), address = ?ptr, symbol_found = !ptr.is_null(), "ucp_put_nbx symbol lookup completed");
        ptr
    }
}

pub fn try_find_real_ucp_ep_flush_nbx() -> *mut c_void {
    use std::ffi::CString;

    debug!(
        pid = std::process::id(),
        "attempting to find real ucp_ep_flush_nbx function"
    );

    // Try multiple approaches to find the real UCX function
    unsafe {
        let symbol_name = CString::new("ucp_ep_flush_nbx").unwrap();

        // First try RTLD_NEXT - this should work for library interposition
        debug!(
            pid = std::process::id(),
            "looking up symbol with RTLD_NEXT: ucp_ep_flush_nbx"
        );
        let mut ptr = libc::dlsym(libc::RTLD_NEXT, symbol_name.as_ptr());

        // Check if we got our own function (infinite recursion trap)
        let our_function_addr = ucp_ep_flush_nbx as *const () as *mut c_void;
        debug!(
            pid = std::process::id(),
            "Our function address: {:?}, RTLD_NEXT returned: {:?}", our_function_addr, ptr
        );
        if ptr == our_function_addr {
            debug!(
                pid = std::process::id(),
                "RTLD_NEXT returned our own function, skipping"
            );
            ptr = std::ptr::null_mut();
        }

        if ptr.is_null() {
            debug!(
                pid = std::process::id(),
                "RTLD_NEXT failed, trying RTLD_DEFAULT"
            );
            ptr = libc::dlsym(libc::RTLD_DEFAULT, symbol_name.as_ptr());
            debug!(pid = std::process::id(), "RTLD_DEFAULT returned: {:?}", ptr);

            // Check again for our own function
            if ptr == our_function_addr {
                debug!(
                    pid = std::process::id(),
                    "RTLD_DEFAULT returned our own function, skipping"
                );
                ptr = std::ptr::null_mut();
            }
        }

        if ptr.is_null() {
            debug!(
                pid = std::process::id(),
                "RTLD_DEFAULT failed, trying to find UCX libraries in loaded modules"
            );

            // First, try to find where UCX is already loaded by reading memory maps
            #[cfg(target_os = "linux")]
            let ucx_lib_paths = {
                let mut paths = Vec::new();
                if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
                    for line in maps.lines() {
                        if line.contains("libucp") {
                            // Extract the library path from the maps line
                            if let Some(path_start) = line.rfind(' ') {
                                let path = &line[path_start + 1..];
                                if path.starts_with('/') && !paths.contains(&path.to_string()) {
                                    paths.push(path.to_string());
                                    debug!(
                                        pid = std::process::id(),
                                        "Found UCX library in memory map: {}", path
                                    );
                                }
                            }
                        }
                    }
                }
                paths
            };

            #[cfg(not(target_os = "linux"))]
            let ucx_lib_paths: Vec<String> = Vec::new();

            // Try to dlopen each found UCX library and look for the symbol
            for lib_path in ucx_lib_paths {
                let lib_path_cstr = CString::new(lib_path.as_str()).unwrap();
                let handle =
                    libc::dlopen(lib_path_cstr.as_ptr(), libc::RTLD_LAZY | libc::RTLD_NOLOAD);
                if !handle.is_null() {
                    ptr = libc::dlsym(handle, symbol_name.as_ptr());
                    if !ptr.is_null() && ptr != our_function_addr {
                        debug!(
                            pid = std::process::id(),
                            "Found ucp_ep_flush_nbx in {}: {:?}", lib_path, ptr
                        );
                        break;
                    }
                    // Note: don't call dlclose since RTLD_NOLOAD just gets a reference
                }
            }
        }

        if ptr.is_null() {
            // Final attempt - try some common UCX library names
            let common_ucx_libs = ["libucp.so.0", "libucp.so", "libucp.dylib"];
            for lib_name in &common_ucx_libs {
                let lib_name_cstr = CString::new(*lib_name).unwrap();
                let handle =
                    libc::dlopen(lib_name_cstr.as_ptr(), libc::RTLD_LAZY | libc::RTLD_NOLOAD);
                if !handle.is_null() {
                    ptr = libc::dlsym(handle, symbol_name.as_ptr());
                    if !ptr.is_null() && ptr != our_function_addr {
                        debug!(
                            pid = std::process::id(),
                            "Found ucp_ep_flush_nbx in {}: {:?}", lib_name, ptr
                        );
                        break;
                    }
                }
            }
        }

        debug!(pid = std::process::id(), address = ?ptr, symbol_found = !ptr.is_null(), "ucp_ep_flush_nbx symbol lookup completed");
        ptr
    }
}

// macro to generate init functions for real UCX function pointers
macro_rules! generate_init_function {
    ($init_fn:ident, $finder_fn:ident, $static_ptr:ident, $symbol_str:literal) => {
        pub fn $init_fn() {
            let ptr = $finder_fn();
            $static_ptr.store(ptr, Ordering::Relaxed);
            debug!(
                pid = std::process::id(),
                ptr_loaded = !ptr.is_null(),
                concat!("real ", $symbol_str, " function pointer stored during init")
            );
        }
    };
}

// helper functions to reduce code duplication in interceptors

// check reentrancy guard and warn if recursive call detected
fn check_reentrancy_guard(fn_name: &str) -> bool {
    if is_in_intercept() {
        warn!(
            pid = std::process::id(),
            "RECURSION DETECTED: {} called while already intercepting", fn_name
        );
        true
    } else {
        false
    }
}

// update call statistics for a specific function
fn update_call_stats(calls_counter: &AtomicU64) {
    LOCAL_STATE.total_calls.fetch_add(1, Ordering::Relaxed);
    calls_counter.fetch_add(1, Ordering::Relaxed);
}

// handle fault injection logic and recording with full parameter capture
#[inline(always)]
fn handle_fault_injection(
    fn_name: &str,
    hook_enabled: &AtomicBool,
    call_num: u32,
    faults_counter: &AtomicU64,
    params: &CallParams,
) -> Option<UcsStatusPtr> {
    if let Some(error_code) = should_inject_fault_for_hook(hook_enabled) {
        // update statistics
        LOCAL_STATE.faults_injected.fetch_add(1, Ordering::Relaxed);
        faults_counter.fetch_add(1, Ordering::Relaxed);
        LOCAL_STATE.calls_since_fault.store(0, Ordering::Relaxed);

        // only record if recording is enabled (off by default for performance)
        if LOCAL_STATE.call_recorder.is_recording_enabled() {
            debug!(
                pid = std::process::id(),
                "recording fault injection call #{}: error_code={}", call_num, error_code
            );
            LOCAL_STATE
                .call_recorder
                .record_call_with_params(true, error_code, params);
        }

        warn!(
            pid = std::process::id(),
            error_code = error_code,
            "[FAULT] INJECTED: {} error ({})",
            fn_name,
            error_code
        );
        Some(ucs_status_to_ptr(error_code))
    } else {
        // only record successful calls if recording is explicitly enabled
        if LOCAL_STATE.call_recorder.is_recording_enabled() {
            debug!(
                pid = std::process::id(),
                "recording successful call #{}", call_num
            );
            LOCAL_STATE
                .call_recorder
                .record_call_with_params(false, 0, params);
        }
        LOCAL_STATE
            .calls_since_fault
            .fetch_add(1, Ordering::Relaxed);
        None
    }
}

// get real function pointer with lazy initialization
fn get_real_function_ptr(
    static_ptr: &AtomicPtr<c_void>,
    finder_fn: fn() -> *mut c_void,
    fn_name: &str,
) -> *mut c_void {
    let mut real_fn_ptr = static_ptr.load(Ordering::Relaxed);

    // if not initialized yet, try to initialize it now
    if real_fn_ptr.is_null() {
        real_fn_ptr = finder_fn();
        if !real_fn_ptr.is_null() {
            static_ptr.store(real_fn_ptr, Ordering::Relaxed);
            debug!(pid = std::process::id(), address = ?real_fn_ptr, "lazy initialized real {} function", fn_name);
        }
    }

    real_fn_ptr
}

// log debug information if enabled
fn log_debug_info_if_enabled(_fn_name: &str, call_num: u32) {
    if DEBUG_ENABLED.load(Ordering::Relaxed) || call_num < 5 {
        let state = get_current_state();
        debug!(
            pid = std::process::id(),
            "Fault state: enabled={}, strategy={}, pattern={:?}, error_codes={:?}",
            state.enabled,
            state.strategy,
            state.pattern,
            state.error_codes
        );
    }
}

// generate init functions using the macro
generate_init_function!(
    init_real_ucp_get_nbx,
    try_find_real_ucp_get_nbx,
    REAL_UCP_GET_NBX,
    "ucp_get_nbx"
);
generate_init_function!(
    init_real_ucp_put_nbx,
    try_find_real_ucp_put_nbx,
    REAL_UCP_PUT_NBX,
    "ucp_put_nbx"
);
generate_init_function!(
    init_real_ucp_ep_flush_nbx,
    try_find_real_ucp_ep_flush_nbx,
    REAL_UCP_EP_FLUSH_NBX,
    "ucp_ep_flush_nbx"
);

// helper function to decide fault injection using local state
pub fn should_inject_fault() -> Option<UcsStatus> {
    let enabled = LOCAL_STATE.enabled.load(Ordering::Relaxed);

    if !enabled {
        return None;
    }

    let mut strategy = LOCAL_STATE.strategy.lock().unwrap();
    strategy.should_inject()
}

// thread-local RNG for lock-free random decisions
thread_local! {
    static THREAD_RNG: std::cell::Cell<u64> = std::cell::Cell::new({
        use std::time::SystemTime;
        let tid = unsafe { libc::pthread_self() as u64 };
        let time = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64;
        tid.wrapping_mul(0x9e3779b97f4a7c15).wrapping_add(time)
    });
}

// fast, lock-free random number generator (xorshift)
#[inline(always)]
fn fast_random() -> u32 {
    THREAD_RNG.with(|rng| {
        let mut x = rng.get();
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        rng.set(x);
        (x % 100) as u32
    })
}

// lock-free random fault injection (hot path - no mutex!)
#[inline(always)]
fn should_inject_lockfree_random() -> Option<UcsStatus> {
    let probability = LOCAL_STATE.random_probability.load(Ordering::Relaxed);
    if probability == 0 {
        return None;
    }

    if fast_random() < probability {
        // use default error code for lock-free path
        Some(crate::ucx::UCS_ERR_IO_ERROR)
    } else {
        None
    }
}

// optimized helper function that takes the hook flag directly (no string matching!)
#[inline(always)]
pub fn should_inject_fault_for_hook(hook_enabled: &AtomicBool) -> Option<UcsStatus> {
    // fast path: check if fault injection is globally enabled
    if !LOCAL_STATE.enabled.load(Ordering::Relaxed) {
        return None;
    }

    // fast path: check if this specific hook is enabled (single atomic load, no string matching!)
    if !hook_enabled.load(Ordering::Relaxed) {
        return None;
    }

    // ultra-fast path: lock-free random strategy (most common case)
    if LOCAL_STATE.use_lockfree_random.load(Ordering::Relaxed) {
        return should_inject_lockfree_random();
    }

    // slow path: pattern/replay strategies require mutex lock
    let mut strategy = LOCAL_STATE.strategy.lock().unwrap();
    strategy.should_inject()
}

// legacy function for backward compatibility (not used in hot path)
pub fn should_inject_fault_for_function(function_name: &str) -> Option<UcsStatus> {
    let hook_enabled = match function_name {
        "ucp_get_nbx" => &LOCAL_STATE.hook_config.ucp_get_nbx_enabled,
        "ucp_put_nbx" => &LOCAL_STATE.hook_config.ucp_put_nbx_enabled,
        "ucp_ep_flush_nbx" => &LOCAL_STATE.hook_config.ucp_ep_flush_nbx_enabled,
        _ => return None,
    };
    should_inject_fault_for_hook(hook_enabled)
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
    const FN_NAME: &str = "ucp_get_nbx";

    // ULTRA-FAST PATH: single atomic check, no thread-local work, no reentrancy guard
    // bypasses everything when fault injection is globally disabled
    if !LOCAL_STATE.enabled.load(Ordering::Relaxed) {
        let real_fn_ptr = REAL_UCP_GET_NBX.load(Ordering::Relaxed);
        if !real_fn_ptr.is_null() {
            let real_fn: extern "C" fn(
                UcpEpH,
                *mut c_void,
                size_t,
                u64,
                UcpRkeyH,
                UcpRequestParamT,
            ) -> UcsStatusPtr = unsafe { std::mem::transmute(real_fn_ptr) };
            return real_fn(ep, buffer, count, remote_addr, rkey, param);
        }
        // fallback: lazy init if not yet initialized
        let real_fn_ptr = try_find_real_ucp_get_nbx();
        if !real_fn_ptr.is_null() {
            REAL_UCP_GET_NBX.store(real_fn_ptr, Ordering::Relaxed);
            let real_fn: extern "C" fn(
                UcpEpH,
                *mut c_void,
                size_t,
                u64,
                UcpRkeyH,
                UcpRequestParamT,
            ) -> UcsStatusPtr = unsafe { std::mem::transmute(real_fn_ptr) };
            return real_fn(ep, buffer, count, remote_addr, rkey, param);
        }
    }

    // Check reentrancy guard (only when fault injection is enabled)
    if check_reentrancy_guard(FN_NAME) {
        return std::ptr::null_mut(); // UCS_OK
    }

    // Set reentrancy guard
    set_in_intercept(true);

    // Update statistics
    update_call_stats(&LOCAL_STATE.ucp_get_nbx_calls);

    // Call numbering for logging
    static CALL_COUNT: AtomicU32 = AtomicU32::new(0);
    let call_num = CALL_COUNT.fetch_add(1, Ordering::Relaxed);

    // Function-specific logging
    if DEBUG_ENABLED.load(Ordering::Relaxed) || call_num < 5 {
        trace!(
            pid = std::process::id(),
            "ucp_get_nbx called #{} - ep: {:?}, buffer: {:?}, count: {}, remote_addr: 0x{:x}, rkey: {:?}, param: {:?}",
            call_num, ep, buffer, count, remote_addr, rkey, param
        );
        log_debug_info_if_enabled(FN_NAME, call_num);
    }

    // Check for fault injection
    let params = CallParams {
        function_type: FunctionType::UcpGetNbx,
        transfer_size: count as u64,
        remote_addr,
        endpoint: ep as u64,
        rkey: rkey as u64,
    };
    if let Some(fault_result) = handle_fault_injection(
        FN_NAME,
        &LOCAL_STATE.hook_config.ucp_get_nbx_enabled,
        call_num,
        &LOCAL_STATE.ucp_get_nbx_faults,
        &params,
    ) {
        set_in_intercept(false);
        return fault_result;
    }

    // Get real function pointer
    let real_fn_ptr = get_real_function_ptr(&REAL_UCP_GET_NBX, try_find_real_ucp_get_nbx, FN_NAME);

    let result = if !real_fn_ptr.is_null() {
        // Cast to function pointer and call
        let real_fn: extern "C" fn(
            UcpEpH,
            *mut c_void,
            size_t,
            u64,
            UcpRkeyH,
            UcpRequestParamT,
        ) -> UcsStatusPtr = unsafe { std::mem::transmute(real_fn_ptr) };

        trace!(pid = std::process::id(), call_num, address = ?real_fn_ptr, "calling real ucp_get_nbx function");
        let result = real_fn(ep, buffer, count, remote_addr, rkey, param);
        trace!(pid = std::process::id(), call_num, result = ?result, result_int = result as isize, "real ucp_get_nbx returned");

        result
    } else {
        error!(
            pid = std::process::id(),
            call_num,
            "real ucp_get_nbx not found, returning IO_ERROR since operation cannot be completed"
        );
        ucs_status_to_ptr(crate::ucx::UCS_ERR_IO_ERROR)
    };

    // Clear reentrancy guard before returning
    set_in_intercept(false);

    result
}

// UCX function interceptor for ucp_put_nbx - remote write operations
#[no_mangle]
pub extern "C" fn ucp_put_nbx(
    ep: UcpEpH,
    buffer: *const c_void,
    count: size_t,
    remote_addr: u64,
    rkey: UcpRkeyH,
    param: UcpRequestParamT,
) -> UcsStatusPtr {
    const FN_NAME: &str = "ucp_put_nbx";

    // ULTRA-FAST PATH: single atomic check, no thread-local work, no reentrancy guard
    if !LOCAL_STATE.enabled.load(Ordering::Relaxed) {
        let real_fn_ptr = REAL_UCP_PUT_NBX.load(Ordering::Relaxed);
        if !real_fn_ptr.is_null() {
            let real_fn: extern "C" fn(
                UcpEpH,
                *const c_void,
                size_t,
                u64,
                UcpRkeyH,
                UcpRequestParamT,
            ) -> UcsStatusPtr = unsafe { std::mem::transmute(real_fn_ptr) };
            return real_fn(ep, buffer, count, remote_addr, rkey, param);
        }
        // fallback: lazy init if not yet initialized
        let real_fn_ptr = try_find_real_ucp_put_nbx();
        if !real_fn_ptr.is_null() {
            REAL_UCP_PUT_NBX.store(real_fn_ptr, Ordering::Relaxed);
            let real_fn: extern "C" fn(
                UcpEpH,
                *const c_void,
                size_t,
                u64,
                UcpRkeyH,
                UcpRequestParamT,
            ) -> UcsStatusPtr = unsafe { std::mem::transmute(real_fn_ptr) };
            return real_fn(ep, buffer, count, remote_addr, rkey, param);
        }
    }

    // Check reentrancy guard (only when fault injection is enabled)
    if check_reentrancy_guard(FN_NAME) {
        return std::ptr::null_mut(); // UCS_OK
    }

    // Set reentrancy guard
    set_in_intercept(true);

    // Update statistics
    update_call_stats(&LOCAL_STATE.ucp_put_nbx_calls);

    // Call numbering for logging
    static CALL_COUNT: AtomicU32 = AtomicU32::new(0);
    let call_num = CALL_COUNT.fetch_add(1, Ordering::Relaxed);

    // Function-specific logging
    if DEBUG_ENABLED.load(Ordering::Relaxed) || call_num < 5 {
        trace!(
            pid = std::process::id(),
            "ucp_put_nbx called #{} - ep: {:?}, buffer: {:?}, count: {}, remote_addr: 0x{:x}, rkey: {:?}, param: {:?}",
            call_num, ep, buffer, count, remote_addr, rkey, param
        );
        log_debug_info_if_enabled(FN_NAME, call_num);
    }

    // Check for fault injection
    let params = CallParams {
        function_type: FunctionType::UcpPutNbx,
        transfer_size: count as u64,
        remote_addr,
        endpoint: ep as u64,
        rkey: rkey as u64,
    };
    if let Some(fault_result) = handle_fault_injection(
        FN_NAME,
        &LOCAL_STATE.hook_config.ucp_put_nbx_enabled,
        call_num,
        &LOCAL_STATE.ucp_put_nbx_faults,
        &params,
    ) {
        set_in_intercept(false);
        return fault_result;
    }

    // Get real function pointer
    let real_fn_ptr = get_real_function_ptr(&REAL_UCP_PUT_NBX, try_find_real_ucp_put_nbx, FN_NAME);

    let result = if !real_fn_ptr.is_null() {
        // Cast to function pointer and call
        let real_fn: extern "C" fn(
            UcpEpH,
            *const c_void,
            size_t,
            u64,
            UcpRkeyH,
            UcpRequestParamT,
        ) -> UcsStatusPtr = unsafe { std::mem::transmute(real_fn_ptr) };

        trace!(pid = std::process::id(), call_num, address = ?real_fn_ptr, "calling real ucp_put_nbx function");
        let result = real_fn(ep, buffer, count, remote_addr, rkey, param);
        trace!(pid = std::process::id(), call_num, result = ?result, result_int = result as isize, "real ucp_put_nbx returned");

        result
    } else {
        error!(
            pid = std::process::id(),
            call_num,
            "real ucp_put_nbx not found, returning IO_ERROR since operation cannot be completed"
        );
        ucs_status_to_ptr(crate::ucx::UCS_ERR_IO_ERROR)
    };

    // Clear reentrancy guard before returning
    set_in_intercept(false);

    result
}

// UCX function interceptor for ucp_ep_flush_nbx - flush operations
#[no_mangle]
pub extern "C" fn ucp_ep_flush_nbx(ep: UcpEpH, param: UcpRequestParamT) -> UcsStatusPtr {
    const FN_NAME: &str = "ucp_ep_flush_nbx";

    // ULTRA-FAST PATH: single atomic check, no thread-local work, no reentrancy guard
    if !LOCAL_STATE.enabled.load(Ordering::Relaxed) {
        let real_fn_ptr = REAL_UCP_EP_FLUSH_NBX.load(Ordering::Relaxed);
        if !real_fn_ptr.is_null() {
            let real_fn: extern "C" fn(UcpEpH, UcpRequestParamT) -> UcsStatusPtr =
                unsafe { std::mem::transmute(real_fn_ptr) };
            return real_fn(ep, param);
        }
        // fallback: lazy init if not yet initialized
        let real_fn_ptr = try_find_real_ucp_ep_flush_nbx();
        if !real_fn_ptr.is_null() {
            REAL_UCP_EP_FLUSH_NBX.store(real_fn_ptr, Ordering::Relaxed);
            let real_fn: extern "C" fn(UcpEpH, UcpRequestParamT) -> UcsStatusPtr =
                unsafe { std::mem::transmute(real_fn_ptr) };
            return real_fn(ep, param);
        }
    }

    // Check reentrancy guard (only when fault injection is enabled)
    if check_reentrancy_guard(FN_NAME) {
        return std::ptr::null_mut(); // UCS_OK
    }

    // Set reentrancy guard
    set_in_intercept(true);

    // Update statistics
    update_call_stats(&LOCAL_STATE.ucp_ep_flush_nbx_calls);

    // Call numbering for logging
    static CALL_COUNT: AtomicU32 = AtomicU32::new(0);
    let call_num = CALL_COUNT.fetch_add(1, Ordering::Relaxed);

    // Function-specific logging
    if DEBUG_ENABLED.load(Ordering::Relaxed) || call_num < 5 {
        trace!(
            pid = std::process::id(),
            "ucp_ep_flush_nbx called #{} - ep: {:?}, param: {:?}",
            call_num,
            ep,
            param
        );
        log_debug_info_if_enabled(FN_NAME, call_num);
    }

    // Check for fault injection (flush has no transfer size/remote addr/rkey)
    let params = CallParams {
        function_type: FunctionType::UcpEpFlushNbx,
        transfer_size: 0,
        remote_addr: 0,
        endpoint: ep as u64,
        rkey: 0,
    };
    if let Some(fault_result) = handle_fault_injection(
        FN_NAME,
        &LOCAL_STATE.hook_config.ucp_ep_flush_nbx_enabled,
        call_num,
        &LOCAL_STATE.ucp_ep_flush_nbx_faults,
        &params,
    ) {
        set_in_intercept(false);
        return fault_result;
    }

    // Get real function pointer
    let real_fn_ptr = get_real_function_ptr(
        &REAL_UCP_EP_FLUSH_NBX,
        try_find_real_ucp_ep_flush_nbx,
        FN_NAME,
    );

    let result = if !real_fn_ptr.is_null() {
        // Cast to function pointer and call
        let real_fn: extern "C" fn(UcpEpH, UcpRequestParamT) -> UcsStatusPtr =
            unsafe { std::mem::transmute(real_fn_ptr) };

        trace!(pid = std::process::id(), call_num, address = ?real_fn_ptr, "calling real ucp_ep_flush_nbx function");
        let result = real_fn(ep, param);
        trace!(pid = std::process::id(), call_num, result = ?result, result_int = result as isize, "real ucp_ep_flush_nbx returned");

        result
    } else {
        error!(pid = std::process::id(), call_num, "real ucp_ep_flush_nbx not found, returning IO_ERROR since operation cannot be completed");
        ucs_status_to_ptr(crate::ucx::UCS_ERR_IO_ERROR)
    };

    // Clear reentrancy guard before returning
    set_in_intercept(false);

    result
}
