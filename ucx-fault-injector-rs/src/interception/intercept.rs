use libc::{c_void, size_t};
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};
use tracing::{debug, warn};
use ucx_fault_injector_macros::ucx_interceptor;

use super::symbol_lookup::find_real_ucx_function;
use crate::ipc::get_current_state;
use crate::recorder::{CallParams, FunctionType};
use crate::state::{is_in_intercept, DEBUG_ENABLED, LOCAL_STATE};
use crate::ucx::{ucs_status_to_ptr, UcpEpH, UcpRequestParamT, UcpRkeyH, UcsStatus, UcsStatusPtr};

// function pointers to real UCX functions - use atomic pointer to avoid deadlock
static REAL_UCP_GET_NBX: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_UCP_PUT_NBX: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_UCP_EP_FLUSH_NBX: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

// simplified finder functions using generic implementation
pub fn try_find_real_ucp_get_nbx() -> *mut c_void {
    let our_addr = ucp_get_nbx as *const () as *mut c_void;
    find_real_ucx_function("ucp_get_nbx", our_addr)
}

pub fn try_find_real_ucp_put_nbx() -> *mut c_void {
    let our_addr = ucp_put_nbx as *const () as *mut c_void;
    find_real_ucx_function("ucp_put_nbx", our_addr)
}

pub fn try_find_real_ucp_ep_flush_nbx() -> *mut c_void {
    let our_addr = ucp_ep_flush_nbx as *const () as *mut c_void;
    find_real_ucx_function("ucp_ep_flush_nbx", our_addr)
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
    LOCAL_STATE
        .stats
        .total_calls
        .fetch_add(1, Ordering::Relaxed);
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
        LOCAL_STATE
            .stats
            .faults_injected
            .fetch_add(1, Ordering::Relaxed);
        faults_counter.fetch_add(1, Ordering::Relaxed);
        LOCAL_STATE
            .stats
            .calls_since_fault
            .store(0, Ordering::Relaxed);

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
            .stats
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

// public version for use by interceptor_framework macro
pub fn log_debug_info_if_enabled_internal(call_num: u32) {
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

// returns 0-9999 for 0.01% precision (scale factor of 100)
#[inline(always)]
fn fast_random() -> u32 {
    fastrand::u32(0..10000)
}

// lock-free random fault injection (hot path - no mutex!)
#[inline(always)]
fn should_inject_lockfree_random() -> Option<UcsStatus> {
    let probability = LOCAL_STATE
        .lockfree_random
        .probability
        .load(Ordering::Relaxed);
    if probability == 0 {
        return None;
    }

    if fast_random() < probability {
        // randomly select from configured error codes
        let count = LOCAL_STATE
            .lockfree_random
            .error_code_count
            .load(Ordering::Relaxed);
        if count == 0 {
            return Some(crate::ucx::UCS_ERR_IO_ERROR); // fallback
        }

        // use fast_random to select error code
        let index = (fast_random() as usize) % count;
        let error_code = LOCAL_STATE.lockfree_random.error_codes[index].load(Ordering::Relaxed);
        Some(error_code)
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
    if LOCAL_STATE.lockfree_random.enabled.load(Ordering::Relaxed) {
        return should_inject_lockfree_random();
    }

    // slow path: pattern/replay strategies require mutex lock
    let mut strategy = LOCAL_STATE.strategy.lock().unwrap();
    strategy.should_inject()
}

// version with debug info for logging PRNG details
#[inline(always)]
pub fn should_inject_fault_for_hook_with_debug(
    hook_enabled: &AtomicBool,
) -> crate::fault::strategy::InjectionDecision {
    use crate::fault::strategy::InjectionDecision;

    // fast path: check if fault injection is globally enabled
    if !LOCAL_STATE.enabled.load(Ordering::Relaxed) {
        return InjectionDecision {
            error_code: None,
            random_value: 0,
            probability: 0,
        };
    }

    // fast path: check if this specific hook is enabled
    if !hook_enabled.load(Ordering::Relaxed) {
        return InjectionDecision {
            error_code: None,
            random_value: 0,
            probability: 0,
        };
    }

    // ultra-fast path: lock-free random strategy (most common case)
    if LOCAL_STATE.lockfree_random.enabled.load(Ordering::Relaxed) {
        let probability = LOCAL_STATE
            .lockfree_random
            .probability
            .load(Ordering::Relaxed);
        let random = fast_random();
        let error_code = if random < probability {
            let count = LOCAL_STATE
                .lockfree_random
                .error_code_count
                .load(Ordering::Relaxed);
            if count == 0 {
                Some(crate::ucx::UCS_ERR_IO_ERROR)
            } else {
                let index = (fast_random() as usize) % count;
                Some(LOCAL_STATE.lockfree_random.error_codes[index].load(Ordering::Relaxed))
            }
        } else {
            None
        };
        return InjectionDecision {
            error_code,
            random_value: random,
            probability,
        };
    }

    // slow path: pattern/replay strategies require mutex lock
    let mut strategy = LOCAL_STATE.strategy.lock().unwrap();
    strategy.should_inject_with_debug()
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

// UCX function interceptors - now generated via proc macro to eliminate boilerplate

#[ucx_interceptor(
    real_fn_static = REAL_UCP_GET_NBX,
    finder_fn = try_find_real_ucp_get_nbx,
    hook_enabled = LOCAL_STATE.hook_config.ucp_get_nbx_enabled,
    calls_counter = LOCAL_STATE.stats.ucp_get_nbx_calls,
    faults_counter = LOCAL_STATE.stats.ucp_get_nbx_faults,
)]
pub extern "C" fn ucp_get_nbx(
    ep: UcpEpH,
    buffer: *mut c_void,
    count: size_t,
    remote_addr: u64,
    rkey: UcpRkeyH,
    param: UcpRequestParamT,
) -> UcsStatusPtr {
    CallParams {
        function_type: FunctionType::UcpGetNbx,
        transfer_size: count as u64,
        remote_addr,
        endpoint: ep as u64,
        rkey: rkey as u64,
    }
}

#[ucx_interceptor(
    real_fn_static = REAL_UCP_PUT_NBX,
    finder_fn = try_find_real_ucp_put_nbx,
    hook_enabled = LOCAL_STATE.hook_config.ucp_put_nbx_enabled,
    calls_counter = LOCAL_STATE.stats.ucp_put_nbx_calls,
    faults_counter = LOCAL_STATE.stats.ucp_put_nbx_faults,
)]
pub extern "C" fn ucp_put_nbx(
    ep: UcpEpH,
    buffer: *const c_void,
    count: size_t,
    remote_addr: u64,
    rkey: UcpRkeyH,
    param: UcpRequestParamT,
) -> UcsStatusPtr {
    CallParams {
        function_type: FunctionType::UcpPutNbx,
        transfer_size: count as u64,
        remote_addr,
        endpoint: ep as u64,
        rkey: rkey as u64,
    }
}

#[ucx_interceptor(
    real_fn_static = REAL_UCP_EP_FLUSH_NBX,
    finder_fn = try_find_real_ucp_ep_flush_nbx,
    hook_enabled = LOCAL_STATE.hook_config.ucp_ep_flush_nbx_enabled,
    calls_counter = LOCAL_STATE.stats.ucp_ep_flush_nbx_calls,
    faults_counter = LOCAL_STATE.stats.ucp_ep_flush_nbx_faults,
)]
pub extern "C" fn ucp_ep_flush_nbx(ep: UcpEpH, param: UcpRequestParamT) -> UcsStatusPtr {
    CallParams {
        function_type: FunctionType::UcpEpFlushNbx,
        transfer_size: 0,
        remote_addr: 0,
        endpoint: ep as u64,
        rkey: 0,
    }
}
