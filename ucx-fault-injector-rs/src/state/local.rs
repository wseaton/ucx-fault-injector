#[cfg(not(test))]
use once_cell::sync::Lazy;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use crate::fault::FaultStrategy;
use crate::recorder::CallRecordBuffer;
use crate::types::HookName;

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

    #[cfg(test)]
    pub const fn new_const() -> Self {
        Self {
            ucp_get_nbx_enabled: AtomicBool::new(true),
            ucp_put_nbx_enabled: AtomicBool::new(true),
            ucp_ep_flush_nbx_enabled: AtomicBool::new(true),
        }
    }

    pub fn enable_hook(&self, name: HookName) {
        match name {
            HookName::UcpGetNbx => self.ucp_get_nbx_enabled.store(true, Ordering::Relaxed),
            HookName::UcpPutNbx => self.ucp_put_nbx_enabled.store(true, Ordering::Relaxed),
            HookName::UcpEpFlushNbx => self.ucp_ep_flush_nbx_enabled.store(true, Ordering::Relaxed),
            HookName::All => self.enable_all(),
        }
    }

    pub fn disable_hook(&self, name: HookName) {
        match name {
            HookName::UcpGetNbx => self.ucp_get_nbx_enabled.store(false, Ordering::Relaxed),
            HookName::UcpPutNbx => self.ucp_put_nbx_enabled.store(false, Ordering::Relaxed),
            HookName::UcpEpFlushNbx => self
                .ucp_ep_flush_nbx_enabled
                .store(false, Ordering::Relaxed),
            HookName::All => self.disable_all(),
        }
    }

    pub fn is_enabled(&self, name: HookName) -> bool {
        match name {
            HookName::UcpGetNbx => self.ucp_get_nbx_enabled.load(Ordering::Relaxed),
            HookName::UcpPutNbx => self.ucp_put_nbx_enabled.load(Ordering::Relaxed),
            HookName::UcpEpFlushNbx => self.ucp_ep_flush_nbx_enabled.load(Ordering::Relaxed),
            HookName::All => {
                self.ucp_get_nbx_enabled.load(Ordering::Relaxed)
                    && self.ucp_put_nbx_enabled.load(Ordering::Relaxed)
                    && self.ucp_ep_flush_nbx_enabled.load(Ordering::Relaxed)
            }
        }
    }

    pub fn enable_all(&self) {
        self.ucp_get_nbx_enabled.store(true, Ordering::Relaxed);
        self.ucp_put_nbx_enabled.store(true, Ordering::Relaxed);
        self.ucp_ep_flush_nbx_enabled.store(true, Ordering::Relaxed);
    }

    pub fn disable_all(&self) {
        self.ucp_get_nbx_enabled.store(false, Ordering::Relaxed);
        self.ucp_put_nbx_enabled.store(false, Ordering::Relaxed);
        self.ucp_ep_flush_nbx_enabled
            .store(false, Ordering::Relaxed);
    }
}

impl Default for HookConfiguration {
    fn default() -> Self {
        Self::new()
    }
}

// max error codes for lock-free storage (8 should be plenty)
pub const MAX_LOCKFREE_ERROR_CODES: usize = 8;

// lock-free random strategy state (hot path optimization)
#[derive(Debug)]
pub struct LockFreeRandomState {
    pub probability: AtomicU32, // 0-10000 scaled percentage (0.01% precision)
    pub enabled: AtomicBool,    // true when using random strategy
    pub error_codes: [AtomicI32; MAX_LOCKFREE_ERROR_CODES],
    pub error_code_count: AtomicUsize,
}

impl LockFreeRandomState {
    fn new() -> Self {
        Self {
            probability: AtomicU32::new(2500), // default 25% (scaled: 25.00 * 100)
            enabled: AtomicBool::new(true),
            error_codes: [
                AtomicI32::new(crate::ucx::UCS_ERR_IO_ERROR),
                AtomicI32::new(crate::ucx::UCS_ERR_UNREACHABLE),
                AtomicI32::new(crate::ucx::UCS_ERR_TIMED_OUT),
                AtomicI32::new(0),
                AtomicI32::new(0),
                AtomicI32::new(0),
                AtomicI32::new(0),
                AtomicI32::new(0),
            ],
            error_code_count: AtomicUsize::new(3), // default 3 codes
        }
    }

    #[cfg(test)]
    pub const fn new_const() -> Self {
        Self {
            probability: AtomicU32::new(2500),
            enabled: AtomicBool::new(true),
            error_codes: [
                AtomicI32::new(crate::ucx::UCS_ERR_IO_ERROR),
                AtomicI32::new(crate::ucx::UCS_ERR_UNREACHABLE),
                AtomicI32::new(crate::ucx::UCS_ERR_TIMED_OUT),
                AtomicI32::new(0),
                AtomicI32::new(0),
                AtomicI32::new(0),
                AtomicI32::new(0),
                AtomicI32::new(0),
            ],
            error_code_count: AtomicUsize::new(3),
        }
    }
}

impl Default for LockFreeRandomState {
    fn default() -> Self {
        Self::new()
    }
}

// global statistics tracking (flat structure for simplicity and performance)
#[derive(Debug)]
pub struct FaultStatistics {
    pub total_calls: AtomicU64,
    pub faults_injected: AtomicU64,
    pub calls_since_fault: AtomicU64,
    // per-function counters
    pub ucp_get_nbx_calls: AtomicU64,
    pub ucp_get_nbx_faults: AtomicU64,
    pub ucp_put_nbx_calls: AtomicU64,
    pub ucp_put_nbx_faults: AtomicU64,
    pub ucp_ep_flush_nbx_calls: AtomicU64,
    pub ucp_ep_flush_nbx_faults: AtomicU64,
}

impl FaultStatistics {
    fn new() -> Self {
        Self {
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

    #[cfg(test)]
    pub const fn new_const() -> Self {
        Self {
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

impl Default for FaultStatistics {
    fn default() -> Self {
        Self::new()
    }
}

// main local process state (no shared memory)
pub struct LocalFaultState {
    pub enabled: AtomicBool,
    pub strategy: Mutex<FaultStrategy>,
    pub hook_config: HookConfiguration,
    pub lockfree_random: LockFreeRandomState,
    pub stats: FaultStatistics,
    pub call_recorder: CallRecordBuffer,
    pub stats_log_interval: AtomicU32, // log stats every N calls (0 = disabled)
}

impl LocalFaultState {
    fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            strategy: Mutex::new(FaultStrategy::default()),
            hook_config: HookConfiguration::default(),
            lockfree_random: LockFreeRandomState::new(),
            stats: FaultStatistics::new(),
            call_recorder: CallRecordBuffer::new(),
            stats_log_interval: AtomicU32::new(64), // default: log every 64 calls
        }
    }

    // const version for test static initialization
    #[cfg(test)]
    pub const fn new_const() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            strategy: Mutex::new(crate::fault::FaultStrategy::new_const()),
            hook_config: HookConfiguration::new_const(),
            lockfree_random: LockFreeRandomState::new_const(),
            stats: FaultStatistics::new_const(),
            call_recorder: CallRecordBuffer::new(),
            stats_log_interval: AtomicU32::new(64),
        }
    }

    // backward compatibility accessors (delegate to new structure)
    #[inline(always)]
    pub fn random_probability(&self) -> &AtomicU32 {
        &self.lockfree_random.probability
    }

    #[inline(always)]
    pub fn use_lockfree_random(&self) -> &AtomicBool {
        &self.lockfree_random.enabled
    }

    #[inline(always)]
    pub fn lockfree_error_codes(&self) -> &[AtomicI32; MAX_LOCKFREE_ERROR_CODES] {
        &self.lockfree_random.error_codes
    }

    #[inline(always)]
    pub fn lockfree_error_code_count(&self) -> &AtomicUsize {
        &self.lockfree_random.error_code_count
    }

    #[inline(always)]
    pub fn total_calls(&self) -> &AtomicU64 {
        &self.stats.total_calls
    }

    #[inline(always)]
    pub fn faults_injected(&self) -> &AtomicU64 {
        &self.stats.faults_injected
    }

    #[inline(always)]
    pub fn calls_since_fault(&self) -> &AtomicU64 {
        &self.stats.calls_since_fault
    }

    #[inline(always)]
    pub fn ucp_get_nbx_calls(&self) -> &AtomicU64 {
        &self.stats.ucp_get_nbx_calls
    }

    #[inline(always)]
    pub fn ucp_get_nbx_faults(&self) -> &AtomicU64 {
        &self.stats.ucp_get_nbx_faults
    }

    #[inline(always)]
    pub fn ucp_put_nbx_calls(&self) -> &AtomicU64 {
        &self.stats.ucp_put_nbx_calls
    }

    #[inline(always)]
    pub fn ucp_put_nbx_faults(&self) -> &AtomicU64 {
        &self.stats.ucp_put_nbx_faults
    }

    #[inline(always)]
    pub fn ucp_ep_flush_nbx_calls(&self) -> &AtomicU64 {
        &self.stats.ucp_ep_flush_nbx_calls
    }

    #[inline(always)]
    pub fn ucp_ep_flush_nbx_faults(&self) -> &AtomicU64 {
        &self.stats.ucp_ep_flush_nbx_faults
    }
}

// Local process state (much safer than shared memory)
#[cfg(not(test))]
pub static LOCAL_STATE: Lazy<LocalFaultState> = Lazy::new(LocalFaultState::new);

// Test-specific version without Lazy to avoid initialization issues
#[cfg(test)]
pub static LOCAL_STATE: LocalFaultState = LocalFaultState::new_const();

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
