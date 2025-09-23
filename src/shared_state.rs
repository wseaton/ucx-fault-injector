use std::sync::atomic::{AtomicBool, AtomicU64, AtomicI32, AtomicU32, Ordering};
use std::mem;
use libc::c_void;
use nix::sys::mman::{mmap, munmap, shm_open, shm_unlink, MapFlags, ProtFlags};
use nix::sys::stat::Mode;
use nix::fcntl::OFlag;
use tracing::{debug, info, warn};
use crate::recorder::{CallRecordBuffer, CallRecordBackup};

const MAGIC_NUMBER: u64 = 0xDEADBEEF12345678;
const VERSION: u32 = 1;
const SHM_NAME: &str = "/ucx_fault_injector_state";

// Page-aligned shared memory structure for cross-process statistics and configuration
#[repr(C, align(4096))]
pub struct SharedFaultState {
    // Header for validation
    pub magic: AtomicU64,           // Magic number for sanity checking
    pub version: AtomicU32,         // Structure version
    pub generation: AtomicU64,      // Incremented when config changes via ZMQ

    // Process tracking for crash detection
    pub ref_count: AtomicU32,       // Number of active processes
    pub last_writer_pid: AtomicI32, // PID of last process to update config
    pub last_update_time: AtomicU64, // Unix timestamp of last update

    // Fault injection configuration (updated via ZMQ)
    pub enabled: AtomicBool,        // Global enable/disable
    pub probability: AtomicU32,     // Fault probability 0-100
    pub strategy_type: AtomicU32,   // 0=Random, 1=Pattern
    pub pattern_position: AtomicU64, // Current position in pattern (for pattern strategy)
    pub error_codes: [AtomicI32; 8], // Supported error codes (UCS_ERR_*)
    pub error_codes_len: AtomicU32,  // Number of valid error codes

    // Pattern synchronization (to prevent data races during updates)
    pub pattern_lock: AtomicBool,   // Write lock for pattern updates

    // Pattern string (fixed size, null-terminated)
    pub pattern: [u8; 256],         // Pattern string (X=fault, O=pass)
    pub pattern_len: AtomicU32,     // Length of pattern string

    // Statistics (incremented by hooked functions)
    pub total_calls: AtomicU64,     // Total number of intercepted calls
    pub faults_injected: AtomicU64, // Number of faults injected
    pub calls_since_fault: AtomicU64, // Calls since last fault (for debugging)

    // Per-function call counters (expandable for other UCX functions)
    pub ucp_get_nbx_calls: AtomicU64,
    pub ucp_get_nbx_faults: AtomicU64,

    // Call recording buffer (embedded in shared memory)
    pub call_recorder: CallRecordBuffer,

    // Reserved space for future expansion (much smaller now due to recorder)
    _reserved: [u8; 256],
}

impl SharedFaultState {
    const fn new() -> Self {
        const ATOMIC_I32_INIT: AtomicI32 = AtomicI32::new(0);

        Self {
            magic: AtomicU64::new(MAGIC_NUMBER),
            version: AtomicU32::new(VERSION),
            generation: AtomicU64::new(0),
            ref_count: AtomicU32::new(0),
            last_writer_pid: AtomicI32::new(0),
            last_update_time: AtomicU64::new(0),
            enabled: AtomicBool::new(false),
            probability: AtomicU32::new(25),
            strategy_type: AtomicU32::new(0), // Default to Random
            pattern_position: AtomicU64::new(0),
            error_codes: [ATOMIC_I32_INIT; 8],
            error_codes_len: AtomicU32::new(0),
            pattern_lock: AtomicBool::new(false),
            pattern: [0u8; 256],
            pattern_len: AtomicU32::new(0),
            total_calls: AtomicU64::new(0),
            faults_injected: AtomicU64::new(0),
            calls_since_fault: AtomicU64::new(0),
            ucp_get_nbx_calls: AtomicU64::new(0),
            ucp_get_nbx_faults: AtomicU64::new(0),
            call_recorder: CallRecordBuffer::new(),
            _reserved: [0u8; 256],
        }
    }

    // Validate shared memory is not corrupted
    pub fn is_valid(&self) -> bool {
        self.magic.load(Ordering::Relaxed) == MAGIC_NUMBER &&
        self.version.load(Ordering::Relaxed) == VERSION
    }

    // Check if the shared memory appears to be abandoned
    pub fn is_stale(&self) -> bool {
        let ref_count = self.ref_count.load(Ordering::Relaxed);

        // If ref_count is 0 and we detect no active processes, consider it stale
        if ref_count == 0 {
            let last_update = self.last_update_time.load(Ordering::Relaxed);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            // Consider stale if ref_count is 0 and last update was > 60 seconds ago
            return now.saturating_sub(last_update) > 60;
        }

        // Also check if the last writer process is still alive (legacy check)
        let pid = self.last_writer_pid.load(Ordering::Relaxed);
        if pid <= 0 {
            return false; // No previous writer
        }

        // Check if process still exists using kill(pid, 0)
        unsafe {
            libc::kill(pid, 0) != 0 && nix::errno::Errno::last() == nix::errno::Errno::ESRCH
        }
    }

    // Reset to default values (called when stale state detected)
    pub fn reset_to_defaults(&self) {
        info!("resetting shared state to defaults due to stale data");
        self.enabled.store(false, Ordering::Relaxed);
        self.probability.store(25, Ordering::Relaxed);
        self.strategy_type.store(0, Ordering::Relaxed); // Random
        self.pattern_position.store(0, Ordering::Relaxed);
        self.error_codes_len.store(0, Ordering::Relaxed);
        self.pattern_len.store(0, Ordering::Relaxed);
        self.pattern_lock.store(false, Ordering::Relaxed);
        self.generation.fetch_add(1, Ordering::Release);
        self.update_writer_info();
    }

    // Update writer tracking info
    pub fn update_writer_info(&self) {
        self.last_writer_pid.store(std::process::id() as i32, Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_update_time.store(now, Ordering::Relaxed);
    }

    // Set pattern for pattern-based strategy (cross-process safe)
    pub fn set_pattern(&self, pattern: &str) {
        if pattern.len() >= self.pattern.len() {
            return; // Pattern too long
        }

        // Acquire exclusive write lock with timeout to avoid deadlock
        let start = std::time::Instant::now();
        while self.pattern_lock.compare_exchange_weak(
            false, true, Ordering::Acquire, Ordering::Relaxed
        ).is_err() {
            if start.elapsed() > std::time::Duration::from_millis(100) {
                warn!("pattern update timeout - aborting to avoid deadlock");
                return;
            }
            std::hint::spin_loop();
        }

        // Critical section: update pattern atomically
        unsafe {
            // First mark pattern as invalid
            self.pattern_len.store(0, Ordering::Relaxed);

            // Clear the pattern array
            std::ptr::write_bytes(self.pattern.as_ptr() as *mut u8, 0, self.pattern.len());

            // Copy new pattern
            let bytes = pattern.as_bytes();
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.pattern.as_ptr() as *mut u8,
                bytes.len()
            );

            // Make pattern valid again
            self.pattern_len.store(pattern.len() as u32, Ordering::Release);
        }

        self.pattern_position.store(0, Ordering::Relaxed); // Reset position
        self.generation.fetch_add(1, Ordering::Release);
        self.update_writer_info();

        // Release write lock
        self.pattern_lock.store(false, Ordering::Release);
    }

    // Get current pattern as string
    pub fn get_pattern(&self) -> String {
        let len = self.pattern_len.load(Ordering::Relaxed) as usize;
        if len == 0 || len > self.pattern.len() {
            return String::new();
        }

        // Safe because we control the length
        let pattern_bytes = &self.pattern[..len];
        String::from_utf8_lossy(pattern_bytes).to_string()
    }

    // Set error codes array (thread-safe)
    pub fn set_error_codes(&self, codes: &[i32]) {
        let count = std::cmp::min(codes.len(), self.error_codes.len());

        for i in 0..count {
            self.error_codes[i].store(codes[i], Ordering::Relaxed);
        }

        // Clear remaining slots
        for i in count..self.error_codes.len() {
            self.error_codes[i].store(0, Ordering::Relaxed);
        }

        self.error_codes_len.store(count as u32, Ordering::Relaxed);
        self.generation.fetch_add(1, Ordering::Release);
        self.update_writer_info();
    }

    // Get error codes as Vec
    pub fn get_error_codes(&self) -> Vec<i32> {
        let len = self.error_codes_len.load(Ordering::Relaxed) as usize;
        let mut result = Vec::with_capacity(len);

        for i in 0..len {
            result.push(self.error_codes[i].load(Ordering::Relaxed));
        }

        result
    }
}

// Shared memory manager
pub struct SharedStateManager {
    ptr: *mut SharedFaultState,
    size: usize,
    created_new: bool,
}

unsafe impl Send for SharedStateManager {}
unsafe impl Sync for SharedStateManager {}

impl SharedStateManager {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let size = mem::size_of::<SharedFaultState>();
        debug!(size, "attempting to create/open shared memory segment");

        // Try to create new shared memory segment
        let (state_ptr, created_new) = match shm_open(
            SHM_NAME,
            OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_RDWR,
            Mode::S_IRUSR | Mode::S_IWUSR,
        ) {
            Ok(fd) => {
                info!("created new shared memory segment");

                // Set size of the shared memory
                nix::unistd::ftruncate(&fd, size as i64)?;

                // Map the memory
                let ptr = unsafe {
                    mmap(
                        None,
                        std::num::NonZeroUsize::new(size).unwrap(),
                        ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                        MapFlags::MAP_SHARED,
                        &fd,
                        0,
                    )?
                };

                // Initialize the structure
                let state_ptr = ptr.as_ptr() as *mut SharedFaultState;
                unsafe {
                    std::ptr::write(state_ptr, SharedFaultState::new());
                    (*state_ptr).ref_count.store(1, Ordering::Relaxed);
                    (*state_ptr).update_writer_info();
                }

                debug!(address = ?state_ptr, "initialized new shared state");

                (state_ptr, true)
            }
            Err(_) => {
                // Segment already exists, try to open it
                debug!("shared memory segment exists, attempting to open");

                let fd = shm_open(
                    SHM_NAME,
                    OFlag::O_RDWR,
                    Mode::empty(),
                )?;

                // Map the existing memory
                let ptr = unsafe {
                    mmap(
                        None,
                        std::num::NonZeroUsize::new(size).unwrap(),
                        ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                        MapFlags::MAP_SHARED,
                        &fd,
                        0,
                    )?
                };

                let state_ptr = ptr.as_ptr() as *mut SharedFaultState;

                // Validate and potentially reset stale state
                unsafe {
                    if !(*state_ptr).is_valid() {
                        warn!("shared memory validation failed, backing up recording data before reinitializing");
                        // backup existing recording data before reinitialization
                        let recording_backup = (*state_ptr).call_recorder.backup_state();

                        std::ptr::write(state_ptr, SharedFaultState::new());
                        (*state_ptr).ref_count.store(1, Ordering::Relaxed);
                        (*state_ptr).update_writer_info();

                        // restore the recording data
                        (*state_ptr).call_recorder.restore_from_backup(recording_backup);
                        info!("restored recording data after reinitialization");
                    } else if (*state_ptr).is_stale() {
                        (*state_ptr).reset_to_defaults();
                        (*state_ptr).ref_count.store(1, Ordering::Relaxed);
                    } else {
                        // Just increment reference count
                        (*state_ptr).ref_count.fetch_add(1, Ordering::Relaxed);
                    }
                }

                info!(address = ?state_ptr, "attached to existing shared state");

                (state_ptr, false)
            }
        };

        Ok(SharedStateManager {
            ptr: state_ptr,
            size,
            created_new,
        })
    }

    pub fn get_state(&self) -> &SharedFaultState {
        unsafe { &*self.ptr }
    }

    pub fn get_generation(&self) -> u64 {
        // Use Acquire to see all writes that happened-before the Release in writers
        self.get_state().generation.load(Ordering::Acquire)
    }
}

impl Drop for SharedStateManager {
    fn drop(&mut self) {
        if self.ptr.is_null() {
            return;
        }

        // Just decrement reference count and unmap from this process
        // NEVER remove the shared memory segment during normal cleanup
        // This prevents the vLLM subprocess inspection issue where the first
        // process creates shared memory, exits, and removes it before workers start
        unsafe {
            (*self.ptr).ref_count.fetch_sub(1, Ordering::AcqRel);
        }

        // Unmap the memory from this process (always safe)
        if let Err(_) = unsafe { munmap(std::ptr::NonNull::new_unchecked(self.ptr as *mut c_void), self.size) } {
            // Silent failure during cleanup to avoid logging issues during destruction
        }

        // Let the shared memory segment persist - it will be cleaned up:
        // 1. By the OS when the system reboots
        // 2. By explicit cleanup tools if needed
        // 3. By the next process that detects all references are stale
        // This is much safer for multi-process scenarios like vLLM
    }
}

// Static manager instance
use once_cell::sync::OnceCell;
static SHARED_STATE_MANAGER: OnceCell<SharedStateManager> = OnceCell::new();

pub fn get_shared_state() -> Option<&'static SharedFaultState> {
    SHARED_STATE_MANAGER.get().map(|manager| manager.get_state())
}

pub fn init_shared_state() -> Result<(), Box<dyn std::error::Error>> {
    SHARED_STATE_MANAGER.get_or_try_init(|| SharedStateManager::new())?;
    info!("shared state initialized successfully");
    Ok(())
}

// Force cleanup of shared memory segment (for debugging/testing)
pub fn force_cleanup_shared_memory() -> Result<(), Box<dyn std::error::Error>> {
    if let Err(e) = shm_unlink(SHM_NAME) {
        debug!(error = %e, "failed to force cleanup shared memory (may not exist)");
    } else {
        info!("forced cleanup of shared memory segment");
    }
    Ok(())
}