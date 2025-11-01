use once_cell::sync::Lazy;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64};
use std::sync::Mutex;
use tracing::info;

use crate::recorder::CallRecordBuffer;
use crate::strategy::FaultStrategy;

// configuration for which UCX function hooks are enabled (using atomics for lock-free access)
#[derive(Debug)]
pub struct HookConfiguration {
    pub ucp_get_nbx_enabled: AtomicBool,
    pub ucp_put_nbx_enabled: AtomicBool,
    pub ucp_ep_flush_nbx_enabled: AtomicBool,
}

impl HookConfiguration {
    pub fn new() -> Self {
        Self {
            ucp_get_nbx_enabled: AtomicBool::new(true), // reads enabled by default
            ucp_put_nbx_enabled: AtomicBool::new(true), // writes enabled by default
            ucp_ep_flush_nbx_enabled: AtomicBool::new(true), // flush enabled by default
        }
    }
}

impl Default for HookConfiguration {
    fn default() -> Self {
        Self::new()
    }
}

// Local process state structure (no shared memory)
pub struct LocalFaultState {
    pub enabled: AtomicBool,
    pub strategy: Mutex<FaultStrategy>,
    pub hook_config: HookConfiguration,

    // lock-free random strategy support (for hot path optimization)
    pub random_probability: AtomicU32, // 0-100 percentage for random strategy
    pub use_lockfree_random: AtomicBool, // true when using random strategy

    // Call recording and statistics (local only)
    pub call_recorder: CallRecordBuffer,
    pub total_calls: AtomicU64,
    pub faults_injected: AtomicU64,
    pub calls_since_fault: AtomicU64,
    pub ucp_get_nbx_calls: AtomicU64,
    pub ucp_get_nbx_faults: AtomicU64,
    pub ucp_put_nbx_calls: AtomicU64,
    pub ucp_put_nbx_faults: AtomicU64,
    pub ucp_ep_flush_nbx_calls: AtomicU64,
    pub ucp_ep_flush_nbx_faults: AtomicU64,
}

impl LocalFaultState {
    fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            strategy: Mutex::new(FaultStrategy::new_random(25)), // default 25%
            hook_config: HookConfiguration::new(),
            random_probability: AtomicU32::new(25), // default 25% matches strategy
            use_lockfree_random: AtomicBool::new(true), // default to random strategy
            call_recorder: CallRecordBuffer::new(),
            total_calls: AtomicU64::new(0),
            faults_injected: AtomicU64::new(0),
            calls_since_fault: AtomicU64::new(0),
            ucp_get_nbx_calls: AtomicU64::new(0),
            ucp_get_nbx_faults: AtomicU64::new(0),
            ucp_put_nbx_calls: AtomicU64::new(0),
            ucp_put_nbx_faults: AtomicU64::new(0),
            ucp_ep_flush_nbx_calls: AtomicU64::new(0),
            ucp_ep_flush_nbx_faults: AtomicU64::new(0),
        }
    }
}

// Local process state (much safer than shared memory)
pub static LOCAL_STATE: Lazy<LocalFaultState> = Lazy::new(|| {
    info!("initializing local fault injection state");
    LocalFaultState::new()
});

// local debug state (not shared)
pub static DEBUG_ENABLED: AtomicBool = AtomicBool::new(false);

// reentrancy guard to prevent infinite recursion
// simplified version without expensive catch_unwind - assumes TLS is always valid during interception
thread_local! {
    static IN_INTERCEPT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub fn is_in_intercept() -> bool {
    IN_INTERCEPT.with(|flag| flag.get())
}

pub fn set_in_intercept(value: bool) {
    IN_INTERCEPT.with(|flag| flag.set(value));
}
