use libc::{c_void, size_t};
use std::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering};
use tracing::{debug, error, info, warn};

use crate::ucx::{UcsStatus, UcsStatusPtr, UcpEpH, UcpRkeyH, UcpRequestParamT, ucs_status_to_ptr};
use crate::state::{DEBUG_ENABLED, LOCAL_STATE, is_in_intercept, set_in_intercept};
use crate::subscriber::get_current_state;

// function pointers to real UCX functions - use atomic pointer to avoid deadlock
static REAL_UCP_GET_NBX: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_UCP_PUT_NBX: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_UCP_EP_FLUSH_NBX: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

// macro to generate symbol lookup functions - reduces repetitive code
macro_rules! generate_symbol_finder {
    ($fn_name:ident, $symbol_str:literal, $our_function:expr) => {
        pub fn $fn_name() -> *mut c_void {
            use std::ffi::CString;

            debug!(pid = std::process::id(), concat!("attempting to find real ", $symbol_str, " function"));

            unsafe {
                let symbol_name = CString::new($symbol_str).unwrap();
                let mut ptr = libc::dlsym(libc::RTLD_NEXT, symbol_name.as_ptr());

                let our_function_addr = $our_function as *const () as *mut c_void;
                if ptr == our_function_addr {
                    ptr = std::ptr::null_mut();
                }

                if ptr.is_null() {
                    ptr = libc::dlsym(libc::RTLD_DEFAULT, symbol_name.as_ptr());
                    if ptr == our_function_addr {
                        ptr = std::ptr::null_mut();
                    }
                }

                debug!(pid = std::process::id(), address = ?ptr, symbol_found = !ptr.is_null(), concat!($symbol_str, " symbol lookup completed"));
                ptr
            }
        }
    };
}


// generate symbol finder functions using the macro
generate_symbol_finder!(try_find_real_ucp_get_nbx, "ucp_get_nbx", ucp_get_nbx);
generate_symbol_finder!(try_find_real_ucp_put_nbx, "ucp_put_nbx", ucp_put_nbx);
generate_symbol_finder!(try_find_real_ucp_ep_flush_nbx, "ucp_ep_flush_nbx", ucp_ep_flush_nbx);

// macro to generate init functions for real UCX function pointers
macro_rules! generate_init_function {
    ($init_fn:ident, $finder_fn:ident, $static_ptr:ident, $symbol_str:literal) => {
        pub fn $init_fn() {
            let ptr = $finder_fn();
            $static_ptr.store(ptr, Ordering::Relaxed);
            debug!(pid = std::process::id(), ptr_loaded = !ptr.is_null(), concat!("real ", $symbol_str, " function pointer stored during init"));
        }
    };
}

// helper functions to reduce code duplication in interceptors

// check reentrancy guard and warn if recursive call detected
fn check_reentrancy_guard(fn_name: &str) -> bool {
    if is_in_intercept() {
        warn!(pid = std::process::id(), "RECURSION DETECTED: {} called while already intercepting", fn_name);
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

// handle fault injection logic and recording
fn handle_fault_injection(fn_name: &str, call_num: u32, faults_counter: &AtomicU64) -> Option<UcsStatusPtr> {
    if let Some(error_code) = should_inject_fault_for_function(fn_name) {
        // Record the fault injection decision in local state
        debug!(pid = std::process::id(), "recording fault injection call #{}: error_code={}", call_num, error_code);
        LOCAL_STATE.call_recorder.record_call(true, error_code);
        LOCAL_STATE.faults_injected.fetch_add(1, Ordering::Relaxed);
        faults_counter.fetch_add(1, Ordering::Relaxed);
        LOCAL_STATE.calls_since_fault.store(0, Ordering::Relaxed);
        debug!(pid = std::process::id(), "fault recorded successfully, total_records={}", LOCAL_STATE.call_recorder.get_total_records());

        warn!(pid = std::process::id(), error_code = error_code, "[FAULT] INJECTED: {} error ({})", fn_name, error_code);
        Some(ucs_status_to_ptr(error_code))
    } else {
        // Record the successful call (no fault injected) in local state
        debug!(pid = std::process::id(), "recording successful call #{}", call_num);
        LOCAL_STATE.call_recorder.record_call(false, 0); // 0 is placeholder, not used for success
        LOCAL_STATE.calls_since_fault.fetch_add(1, Ordering::Relaxed);
        debug!(pid = std::process::id(), "success recorded, total_records={}", LOCAL_STATE.call_recorder.get_total_records());
        None
    }
}

// get real function pointer with lazy initialization
fn get_real_function_ptr(static_ptr: &AtomicPtr<c_void>, finder_fn: fn() -> *mut c_void, fn_name: &str) -> *mut c_void {
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
        info!(
            pid = std::process::id(),
            "Fault state: enabled={}, strategy={}, pattern={:?}, error_codes={:?}",
            state.enabled, state.strategy, state.pattern, state.error_codes
        );
    }
}

// generate init functions using the macro
generate_init_function!(init_real_ucp_get_nbx, try_find_real_ucp_get_nbx, REAL_UCP_GET_NBX, "ucp_get_nbx");
generate_init_function!(init_real_ucp_put_nbx, try_find_real_ucp_put_nbx, REAL_UCP_PUT_NBX, "ucp_put_nbx");
generate_init_function!(init_real_ucp_ep_flush_nbx, try_find_real_ucp_ep_flush_nbx, REAL_UCP_EP_FLUSH_NBX, "ucp_ep_flush_nbx");

// helper function to decide fault injection using local state
pub fn should_inject_fault() -> Option<UcsStatus> {
    let enabled = LOCAL_STATE.enabled.load(Ordering::Relaxed);

    if !enabled {
        return None;
    }

    let mut strategy = LOCAL_STATE.strategy.lock().unwrap();
    strategy.should_inject()
}

// helper function to decide fault injection for specific function
pub fn should_inject_fault_for_function(function_name: &str) -> Option<UcsStatus> {
    let enabled = LOCAL_STATE.enabled.load(Ordering::Relaxed);

    if !enabled {
        return None;
    }

    // Check if this specific hook is enabled
    let hook_config = LOCAL_STATE.hook_config.lock().unwrap();
    let hook_enabled = match function_name {
        "ucp_get_nbx" => hook_config.ucp_get_nbx_enabled,
        "ucp_put_nbx" => hook_config.ucp_put_nbx_enabled,
        "ucp_ep_flush_nbx" => hook_config.ucp_ep_flush_nbx_enabled,
        _ => false,
    };

    if !hook_enabled {
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
    const FN_NAME: &str = "ucp_get_nbx";

    // Check reentrancy guard
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
        info!(
            pid = std::process::id(),
            "ucp_get_nbx called #{} - ep: {:?}, buffer: {:?}, count: {}, remote_addr: 0x{:x}, rkey: {:?}, param: {:?}",
            call_num, ep, buffer, count, remote_addr, rkey, param
        );
        log_debug_info_if_enabled(FN_NAME, call_num);
    }

    // Check for fault injection
    if let Some(fault_result) = handle_fault_injection(FN_NAME, call_num, &LOCAL_STATE.ucp_get_nbx_faults) {
        set_in_intercept(false);
        return fault_result;
    }

    // Get real function pointer
    let real_fn_ptr = get_real_function_ptr(&REAL_UCP_GET_NBX, try_find_real_ucp_get_nbx, FN_NAME);

    let result = if !real_fn_ptr.is_null() {
        // Cast to function pointer and call
        let real_fn: extern "C" fn(UcpEpH, *mut c_void, size_t, u64, UcpRkeyH, UcpRequestParamT) -> UcsStatusPtr =
            unsafe { std::mem::transmute(real_fn_ptr) };

        info!(pid = std::process::id(), call_num, address = ?real_fn_ptr, "calling real ucp_get_nbx function");
        let result = real_fn(ep, buffer, count, remote_addr, rkey, param);
        info!(pid = std::process::id(), call_num, result = ?result, result_int = result as isize, "real ucp_get_nbx returned");

        result
    } else {
        error!(pid = std::process::id(), call_num, "real ucp_get_nbx not found, returning IO_ERROR since operation cannot be completed");
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

    // Check reentrancy guard
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
        info!(
            pid = std::process::id(),
            "ucp_put_nbx called #{} - ep: {:?}, buffer: {:?}, count: {}, remote_addr: 0x{:x}, rkey: {:?}, param: {:?}",
            call_num, ep, buffer, count, remote_addr, rkey, param
        );
        log_debug_info_if_enabled(FN_NAME, call_num);
    }

    // Check for fault injection
    if let Some(fault_result) = handle_fault_injection(FN_NAME, call_num, &LOCAL_STATE.ucp_put_nbx_faults) {
        set_in_intercept(false);
        return fault_result;
    }

    // Get real function pointer
    let real_fn_ptr = get_real_function_ptr(&REAL_UCP_PUT_NBX, try_find_real_ucp_put_nbx, FN_NAME);

    let result = if !real_fn_ptr.is_null() {
        // Cast to function pointer and call
        let real_fn: extern "C" fn(UcpEpH, *const c_void, size_t, u64, UcpRkeyH, UcpRequestParamT) -> UcsStatusPtr =
            unsafe { std::mem::transmute(real_fn_ptr) };

        info!(pid = std::process::id(), call_num, address = ?real_fn_ptr, "calling real ucp_put_nbx function");
        let result = real_fn(ep, buffer, count, remote_addr, rkey, param);
        info!(pid = std::process::id(), call_num, result = ?result, result_int = result as isize, "real ucp_put_nbx returned");

        result
    } else {
        error!(pid = std::process::id(), call_num, "real ucp_put_nbx not found, returning IO_ERROR since operation cannot be completed");
        ucs_status_to_ptr(crate::ucx::UCS_ERR_IO_ERROR)
    };

    // Clear reentrancy guard before returning
    set_in_intercept(false);

    result
}

// UCX function interceptor for ucp_ep_flush_nbx - flush operations
#[no_mangle]
pub extern "C" fn ucp_ep_flush_nbx(
    ep: UcpEpH,
    param: UcpRequestParamT,
) -> UcsStatusPtr {
    const FN_NAME: &str = "ucp_ep_flush_nbx";

    // Check reentrancy guard
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
        info!(
            pid = std::process::id(),
            "ucp_ep_flush_nbx called #{} - ep: {:?}, param: {:?}",
            call_num, ep, param
        );
        log_debug_info_if_enabled(FN_NAME, call_num);
    }

    // Check for fault injection
    if let Some(fault_result) = handle_fault_injection(FN_NAME, call_num, &LOCAL_STATE.ucp_ep_flush_nbx_faults) {
        set_in_intercept(false);
        return fault_result;
    }

    // Get real function pointer
    let real_fn_ptr = get_real_function_ptr(&REAL_UCP_EP_FLUSH_NBX, try_find_real_ucp_ep_flush_nbx, FN_NAME);

    let result = if !real_fn_ptr.is_null() {
        // Cast to function pointer and call
        let real_fn: extern "C" fn(UcpEpH, UcpRequestParamT) -> UcsStatusPtr =
            unsafe { std::mem::transmute(real_fn_ptr) };

        info!(pid = std::process::id(), call_num, address = ?real_fn_ptr, "calling real ucp_ep_flush_nbx function");
        let result = real_fn(ep, param);
        info!(pid = std::process::id(), call_num, result = ?result, result_int = result as isize, "real ucp_ep_flush_nbx returned");

        result
    } else {
        error!(pid = std::process::id(), call_num, "real ucp_ep_flush_nbx not found, returning IO_ERROR since operation cannot be completed");
        ucs_status_to_ptr(crate::ucx::UCS_ERR_IO_ERROR)
    };

    // Clear reentrancy guard before returning
    set_in_intercept(false);

    result
}