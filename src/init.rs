use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::atomic::Ordering;
use nix::fcntl::{Flock, FlockArg};
use tracing::{debug, error, info};

use crate::state::{DEBUG_ENABLED, LOCAL_STATE};
use crate::subscriber::{get_current_state, start_zmq_subscriber};
use crate::intercept::init_real_ucp_get_nbx;

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
        let ucp_put_default = libc::dlsym(libc::RTLD_DEFAULT, c"ucp_put".as_ptr() as *const i8);
        let ucp_put_next = libc::dlsym(libc::RTLD_NEXT, c"ucp_put".as_ptr() as *const i8);

        debug!(address = ?ucp_put_default, "ucp_put via RTLD_DEFAULT");
        debug!(address = ?ucp_put_next, "ucp_put via RTLD_NEXT");

        let ucp_get_default = libc::dlsym(libc::RTLD_DEFAULT, c"ucp_get".as_ptr() as *const i8);
        let ucp_get_next = libc::dlsym(libc::RTLD_NEXT, c"ucp_get".as_ptr() as *const i8);

        debug!(address = ?ucp_get_default, "ucp_get via RTLD_DEFAULT");
        debug!(address = ?ucp_get_next, "ucp_get via RTLD_NEXT");
    }

    debug!("=== end library debug information ===");
}

// public initialization function for tests or manual initialization
pub fn init_fault_injector() {
    init_tracing();

    let current_pid = std::process::id();

    // Check if already initialized using file locking
    if is_already_initialized() {
        info!(pid = current_pid, "UCX fault injector already initialized, skipping");
        return;
    }

    info!("UCX fault injector loaded (Rust version)");
    info!(pid = current_pid, "initialization starting");

    // check for debug mode
    if std::env::var("UCX_FAULT_DEBUG").is_ok() {
        DEBUG_ENABLED.store(true, Ordering::Relaxed);
        info!("debug mode enabled via UCX_FAULT_DEBUG environment variable");
    }

    // initialize local state (much safer than shared memory)
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

    // start ZMQ subscriber
    info!("starting ZMQ subscriber");
    start_zmq_subscriber();
    info!(address = "tcp://127.0.0.1:15559", "ZMQ subscriber started");

    info!("ZMQ broadcast commands:");
    info!("  {{\"command\": \"toggle\"}} - toggle fault injection");
    info!("  {{\"command\": \"set_probability\", \"value\": 0-100}} - set fault probability");
    info!("  {{\"command\": \"set_strategy\", \"pattern\": \"random\"}} - use random strategy");
    info!("  {{\"command\": \"set_strategy\", \"pattern\": \"XOOOOXOO\"}} - use pattern strategy");
    info!("  {{\"command\": \"set_strategy\", \"pattern\": \"random\", \"error_codes\": [-3,-6,-20]}} - random with error codes");
    info!("  {{\"command\": \"set_strategy\", \"pattern\": \"XOX\", \"error_codes\": [-3,-6]}} - pattern with error codes");
    info!("  {{\"command\": \"set_error_codes\", \"error_codes\": [-3,-6,-20]}} - update error codes for current strategy");
    info!("  {{\"command\": \"reset\"}} - reset to defaults");
    info!("  {{\"command\": \"status\"}} - get current state");

    // Force initialization of real functions to check symbol loading
    debug!("initializing real UCX function pointer");
    init_real_ucp_get_nbx();

    // Print detailed debug info if debug mode is enabled
    if DEBUG_ENABLED.load(Ordering::Relaxed) {
        print_library_debug_info();
    }

    info!("UCX fault injector initialization complete");
    info!("to enable debug output, set UCX_FAULT_DEBUG=1 in environment");
}

// automatic initialization via constructor (disabled during tests)
#[cfg(not(test))]
#[ctor::ctor]
fn auto_init_fault_injector() {
    init_fault_injector();
}