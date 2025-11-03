//! atomic utilities to reduce boilerplate and hide complexity

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// atomic counter with ergonomic API
#[derive(Debug)]
pub struct AtomicCounter {
    value: AtomicU64,
}

impl AtomicCounter {
    pub const fn new(initial: u64) -> Self {
        Self {
            value: AtomicU64::new(initial),
        }
    }

    #[inline]
    pub fn increment(&self) -> u64 {
        self.value.fetch_add(1, Ordering::Relaxed)
    }

    #[inline]
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    pub fn reset(&self) {
        self.value.store(0, Ordering::Relaxed);
    }
}

/// per-function statistics with paired calls/faults counters
#[derive(Debug)]
pub struct FunctionStats {
    pub calls: AtomicCounter,
    pub faults: AtomicCounter,
}

impl FunctionStats {
    pub const fn new() -> Self {
        Self {
            calls: AtomicCounter::new(0),
            faults: AtomicCounter::new(0),
        }
    }

    #[inline]
    pub fn record_call(&self) {
        self.calls.increment();
    }

    #[inline]
    pub fn record_fault(&self) {
        self.faults.increment();
    }

    pub fn snapshot(&self) -> (u64, u64) {
        (self.calls.get(), self.faults.get())
    }

    pub fn reset(&self) {
        self.calls.reset();
        self.faults.reset();
    }
}

impl Default for FunctionStats {
    fn default() -> Self {
        Self::new()
    }
}

/// helper to sync lock-free error codes
pub fn sync_lockfree_error_codes(
    codes: &[i32],
    use_lockfree: &AtomicBool,
    lockfree_codes: &[std::sync::atomic::AtomicI32],
    lockfree_count: &std::sync::atomic::AtomicUsize,
) {
    if use_lockfree.load(Ordering::Relaxed) {
        let count = codes.len().min(lockfree_codes.len());
        for (i, &code) in codes.iter().take(count).enumerate() {
            lockfree_codes[i].store(code, Ordering::Relaxed);
        }
        lockfree_count.store(count, Ordering::Relaxed);
    }
}
