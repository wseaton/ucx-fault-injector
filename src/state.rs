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
// use a function that can handle thread local storage destruction gracefully
pub fn is_in_intercept() -> bool {
    thread_local! {
        static IN_INTERCEPT: std::cell::RefCell<bool> = const { std::cell::RefCell::new(false) };
    }

    // safely access thread local, returning false if TLS is destroyed
    std::panic::catch_unwind(|| {
        IN_INTERCEPT.with(|flag| *flag.borrow())
    }).unwrap_or(false)
}

pub fn set_in_intercept(value: bool) {
    thread_local! {
        static IN_INTERCEPT: std::cell::RefCell<bool> = const { std::cell::RefCell::new(false) };
    }

    // safely set thread local, ignoring if TLS is destroyed
    let _ = std::panic::catch_unwind(|| {
        IN_INTERCEPT.with(|flag| *flag.borrow_mut() = value)
    });
}