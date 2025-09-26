use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::atomic::Ordering;
use nix::fcntl::{Flock, FlockArg};
use tracing::{debug, error, info, warn};

use crate::state::{DEBUG_ENABLED, LOCAL_STATE};
use crate::subscriber::{get_current_state, start_file_watcher};
use crate::intercept::{init_real_ucp_get_nbx, init_real_ucp_put_nbx, init_real_ucp_ep_flush_nbx};

// initialize tracing subscriber
pub fn init_tracing() {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ucx_fault_injector=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}

// helper function to check if injector is already initialized for this process tree
pub fn is_already_initialized() -> bool {
    let current_pid = std::process::id();

    // Use session ID to prevent reinitialization across fork/exec in same session
    let session_id = unsafe { libc::getsid(0) };
    let lock_file_path = format!("/tmp/ucx-fault-injector-session-{}.lock", session_id);

    // Try to open and lock the file
    match OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&lock_file_path)
    {
        Ok(file) => {
            // Try to acquire exclusive lock (non-blocking)
            match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
                Ok(locked_file) => {
                    // We got the lock, write our PID and keep the file open
                    use std::io::Write;

                    if let Err(e) = writeln!(&*locked_file, "session_{}_pid_{}", session_id, current_pid) {
                        error!(error = %e, "failed to write session/PID to lock file");
                    }

                    // Store the file descriptor so we keep the lock
                    // In a real implementation, we'd store this somewhere static
                    // For now, we'll leak the file descriptor intentionally
                    std::mem::forget(locked_file);
                    false // Not already initialized
                }
                Err((_, _)) => {
                    // Lock failed, someone else has it
                    true // Already initialized
                }
            }
        }
        Err(e) => {
            error!(lock_file_path, error = %e, "failed to create lock file");
            false // Assume not initialized on error
        }
    }
}

// helper function to print debug info about loaded libraries
pub fn print_library_debug_info() {
    debug!("=== library debug information ===");

    // Try to read /proc/self/maps to see loaded libraries
    if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
        debug!("looking for UCX libraries in process memory map:");
        for line in maps.lines() {
            if line.contains("libucp") || line.contains("libucs") || line.contains("ucx") {
                debug!(line = %line, "UCX library found");
            }
        }
    }

    // Check if we can find UCX symbols using different methods
    unsafe {
        let ucp_put_default = libc::dlsym(libc::RTLD_DEFAULT, c"ucp_put".as_ptr());
        let ucp_put_next = libc::dlsym(libc::RTLD_NEXT, c"ucp_put".as_ptr());

        debug!(address = ?ucp_put_default, "ucp_put via RTLD_DEFAULT");
        debug!(address = ?ucp_put_next, "ucp_put via RTLD_NEXT");

        let ucp_get_default = libc::dlsym(libc::RTLD_DEFAULT, c"ucp_get".as_ptr());
        let ucp_get_next = libc::dlsym(libc::RTLD_NEXT, c"ucp_get".as_ptr());

        debug!(address = ?ucp_get_default, "ucp_get via RTLD_DEFAULT");
        debug!(address = ?ucp_get_next, "ucp_get via RTLD_NEXT");
    }

    debug!("=== end library debug information ===");
}

// public initialization function for tests or manual initialization
pub fn init_fault_injector() {
    init_tracing();

    let current_pid = std::process::id();

    // Check if function interception is already initialized using file locking
    let function_intercept_already_initialized = is_already_initialized();

    if !function_intercept_already_initialized {
        info!("UCX fault injector loaded (Rust version)");
        info!(pid = current_pid, "initialization starting");

        // Clear old command file to prevent replay of stale commands
        let command_file = "/tmp/ucx-fault-commands";
        if std::path::Path::new(command_file).exists() {
            if let Err(e) = std::fs::remove_file(command_file) {
                warn!(command_file, error = %e, "failed to clear old command file");
            } else {
                info!(command_file, "cleared old command file to prevent stale command replay");
            }
        }

        // Force initialization of real functions to check symbol loading
        debug!("initializing real UCX function pointers");
        init_real_ucp_get_nbx();
        init_real_ucp_put_nbx();
        init_real_ucp_ep_flush_nbx();

        // Print detailed debug info if debug mode is enabled
        if DEBUG_ENABLED.load(Ordering::Relaxed) {
            print_library_debug_info();
        }

        // register atexit handler as backup cleanup mechanism
        unsafe {
            libc::atexit(atexit_cleanup);
        }

        info!("UCX fault injector function interception initialization complete");
    } else {
        info!(pid = current_pid, "UCX fault injector function interception already initialized, skipping function setup");
    }

    // check for debug mode
    if std::env::var("UCX_FAULT_DEBUG").is_ok() {
        DEBUG_ENABLED.store(true, Ordering::Relaxed);
        info!("debug mode enabled via UCX_FAULT_DEBUG environment variable");
    }

    // shared state removed - using local state only for simplicity and reliability

    // Always initialize local state for each process (needed for file watcher)
    let _ = &*LOCAL_STATE; // Force initialization
    let state = get_current_state();
    info!(
        enabled = state.enabled,
        strategy = %state.strategy,
        probability = state.probability,
        pattern = ?state.pattern,
        error_codes = ?state.error_codes,
        "local process state initialized"
    );

    // Always start file watcher for each process - this ensures commands reach all PIDs
    info!("starting file watcher for commands");
    start_file_watcher();
    info!(command_file = "/tmp/ucx-fault-commands", "file watcher started");

    if !function_intercept_already_initialized {
        info!("file-based commands:");
        info!("  Use ucx-fault-client to send commands via file");
        info!("  Examples: ./ucx-fault-client toggle");
        info!("           ./ucx-fault-client probability 50");
        info!("           ./ucx-fault-client record-dump");
        info!("           ./ucx-fault-client status");
    }

    info!(pid = current_pid, "UCX fault injector process initialization complete");
    if !function_intercept_already_initialized {
        info!("to enable debug output, set UCX_FAULT_DEBUG=1 in environment");
    }
}

// automatic initialization via constructor (disabled during tests)
#[cfg(not(test))]
#[ctor::ctor]
fn auto_init_fault_injector() {
    init_fault_injector();
}

// shared cleanup function for both dtor and atexit
fn perform_cleanup() {
    use std::sync::atomic::{AtomicBool, Ordering};

    static CLEANUP_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

    // Use atomic CAS to ensure only one cleanup happens, avoiding deadlock from signal + dtor
    if CLEANUP_IN_PROGRESS.compare_exchange(
        false, true, Ordering::AcqRel, Ordering::Relaxed
    ).is_ok() {
        // Avoid logging during destruction as it might trigger thread-local access
        // that can panic if TLS is already destroyed

        // The SharedStateManager Drop implementation will handle:
        // - Decrementing reference counter in shared memory
        // - Unmapping shared memory from this process
        // - Removing shared memory segment if this is the last process

        // Note: Local state cleanup happens automatically via Drop impls

        CLEANUP_IN_PROGRESS.store(false, Ordering::Release);
    }
    // Silent cleanup - don't log anything as it might trigger TLS access during destruction
}

// register atexit handler as backup cleanup (called in all processes)
extern "C" fn atexit_cleanup() {
    perform_cleanup();
}

// automatic cleanup via destructor (disabled during tests)
#[cfg(not(test))]
#[ctor::dtor]
fn auto_cleanup_fault_injector() {
    perform_cleanup();
}