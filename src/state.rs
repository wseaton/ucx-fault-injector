use once_cell::sync::Lazy;
use std::sync::atomic::AtomicBool;
use std::sync::Mutex;
use tracing::info;

use crate::strategy::FaultStrategy;

// Local process state structure (no shared memory)
pub struct LocalFaultState {
    pub enabled: AtomicBool,
    pub strategy: Mutex<FaultStrategy>,
}

impl LocalFaultState {
    fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            strategy: Mutex::new(FaultStrategy::new_random(25)), // default 25%
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
thread_local! {
    pub static IN_INTERCEPT: std::cell::RefCell<bool> = const { std::cell::RefCell::new(false) };
}