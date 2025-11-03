use nix::fcntl::{Flock, FlockArg};
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::atomic::Ordering;
use tracing::{debug, error, info, warn};

use crate::fault::FaultStrategy;
use crate::interception::{
    init_real_ucp_ep_flush_nbx, init_real_ucp_get_nbx, init_real_ucp_put_nbx,
};
use crate::ipc::{get_current_state, start_file_watcher, start_socket_server};
use crate::state::{DEBUG_ENABLED, LOCAL_STATE};
use crate::types::Probability;
use crate::version_info;

// environment variable configuration
#[derive(Debug, Clone)]
struct EnvConfig {
    enabled: Option<bool>,
    strategy: Option<String>,
    probability: Option<u32>,
    pattern: Option<String>,
    error_codes: Option<Vec<i32>>,
    hooks: Option<Vec<String>>,
    ipc_enable: bool,
    debug: bool,
}

impl EnvConfig {
    fn from_env() -> Self {
        let enabled = std::env::var("UCX_FAULT_ENABLED")
            .ok()
            .and_then(|v| v.parse::<bool>().ok().or_else(|| Some(v == "1")));

        let strategy = std::env::var("UCX_FAULT_STRATEGY").ok();

        let probability = std::env::var("UCX_FAULT_PROBABILITY")
            .ok()
            .and_then(|v| v.parse::<Probability>().ok())
            .map(|p| p.scaled());

        let pattern = std::env::var("UCX_FAULT_PATTERN").ok();

        let error_codes = std::env::var("UCX_FAULT_ERROR_CODES").ok().and_then(|v| {
            v.split(',')
                .map(|s| s.trim().parse::<i32>())
                .collect::<Result<Vec<_>, _>>()
                .ok()
        });

        let hooks = std::env::var("UCX_FAULT_HOOKS")
            .ok()
            .map(|v| v.split(',').map(|s| s.trim().to_string()).collect());

        let ipc_enable = std::env::var("UCX_FAULT_IPC_ENABLE").is_ok();

        let debug = std::env::var("UCX_FAULT_DEBUG").is_ok();

        Self {
            enabled,
            strategy,
            probability,
            pattern,
            error_codes,
            hooks,
            ipc_enable,
            debug,
        }
    }

    fn apply(&self) {
        info!("applying environment variable configuration");

        // set debug mode first
        if self.debug {
            DEBUG_ENABLED.store(true, Ordering::Relaxed);
            info!("debug mode enabled via UCX_FAULT_DEBUG");
        }

        // configure hooks (default: all enabled)
        if let Some(ref hooks) = self.hooks {
            // disable all first if specific hooks requested
            LOCAL_STATE
                .hook_config
                .ucp_get_nbx_enabled
                .store(false, Ordering::Relaxed);
            LOCAL_STATE
                .hook_config
                .ucp_put_nbx_enabled
                .store(false, Ordering::Relaxed);
            LOCAL_STATE
                .hook_config
                .ucp_ep_flush_nbx_enabled
                .store(false, Ordering::Relaxed);

            for hook in hooks {
                match hook.as_str() {
                    "ucp_get_nbx" | "get" => {
                        LOCAL_STATE
                            .hook_config
                            .ucp_get_nbx_enabled
                            .store(true, Ordering::Relaxed);
                        info!("enabled hook: ucp_get_nbx");
                    }
                    "ucp_put_nbx" | "put" => {
                        LOCAL_STATE
                            .hook_config
                            .ucp_put_nbx_enabled
                            .store(true, Ordering::Relaxed);
                        info!("enabled hook: ucp_put_nbx");
                    }
                    "ucp_ep_flush_nbx" | "flush" => {
                        LOCAL_STATE
                            .hook_config
                            .ucp_ep_flush_nbx_enabled
                            .store(true, Ordering::Relaxed);
                        info!("enabled hook: ucp_ep_flush_nbx");
                    }
                    "all" => {
                        LOCAL_STATE
                            .hook_config
                            .ucp_get_nbx_enabled
                            .store(true, Ordering::Relaxed);
                        LOCAL_STATE
                            .hook_config
                            .ucp_put_nbx_enabled
                            .store(true, Ordering::Relaxed);
                        LOCAL_STATE
                            .hook_config
                            .ucp_ep_flush_nbx_enabled
                            .store(true, Ordering::Relaxed);
                        info!("enabled all hooks");
                    }
                    _ => warn!(hook = %hook, "unknown hook name, ignoring"),
                }
            }
        }

        // configure strategy
        let mut strategy = LOCAL_STATE.strategy.lock().unwrap();

        match self.strategy.as_deref() {
            Some("random") | None => {
                let prob = self.probability.unwrap_or(25);
                if let Some(ref codes) = self.error_codes {
                    *strategy = FaultStrategy::new_random_with_codes(prob, codes.clone());
                    info!(probability = prob, error_codes = ?codes, "configured random strategy from env");

                    // sync lock-free error codes (up to MAX_LOCKFREE_ERROR_CODES)
                    let count = codes.len().min(crate::state::MAX_LOCKFREE_ERROR_CODES);
                    for (i, &code) in codes.iter().take(count).enumerate() {
                        LOCAL_STATE.lockfree_random.error_codes[i].store(code, Ordering::Relaxed);
                    }
                    LOCAL_STATE
                        .lockfree_random
                        .error_code_count
                        .store(count, Ordering::Relaxed);
                } else {
                    *strategy = FaultStrategy::new_random(prob);
                    info!(probability = prob, "configured random strategy from env");

                    // use default error codes
                    LOCAL_STATE.lockfree_random.error_codes[0]
                        .store(crate::ucx::UCS_ERR_IO_ERROR, Ordering::Relaxed);
                    LOCAL_STATE.lockfree_random.error_codes[1]
                        .store(crate::ucx::UCS_ERR_UNREACHABLE, Ordering::Relaxed);
                    LOCAL_STATE.lockfree_random.error_codes[2]
                        .store(crate::ucx::UCS_ERR_TIMED_OUT, Ordering::Relaxed);
                    LOCAL_STATE
                        .lockfree_random
                        .error_code_count
                        .store(3, Ordering::Relaxed);
                }
                // sync lock-free atomics
                LOCAL_STATE
                    .lockfree_random
                    .probability
                    .store(prob, Ordering::Relaxed);
                LOCAL_STATE
                    .lockfree_random
                    .enabled
                    .store(true, Ordering::Relaxed);
            }
            Some("pattern") => {
                if let Some(ref pattern) = self.pattern {
                    if let Some(ref codes) = self.error_codes {
                        *strategy =
                            FaultStrategy::new_pattern_with_codes(pattern.clone(), codes.clone());
                        info!(pattern = %pattern, error_codes = ?codes, "configured pattern strategy from env");
                    } else {
                        *strategy = FaultStrategy::new_pattern(pattern.clone());
                        info!(pattern = %pattern, "configured pattern strategy from env");
                    }
                    LOCAL_STATE
                        .lockfree_random
                        .enabled
                        .store(false, Ordering::Relaxed);
                } else {
                    warn!("pattern strategy requested but no UCX_FAULT_PATTERN provided, using default random");
                }
            }
            Some(other) => {
                warn!(strategy = %other, "unknown strategy, using default random");
            }
        }
        drop(strategy);

        // enable fault injection if requested
        if let Some(enabled) = self.enabled {
            LOCAL_STATE.enabled.store(enabled, Ordering::Relaxed);
            info!(
                enabled,
                "fault injection {}",
                if enabled { "ENABLED" } else { "DISABLED" }
            );
        } else {
            info!("fault injection DISABLED by default (set UCX_FAULT_ENABLED=1 to enable)");
        }
    }
}

// IPC backend selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpcBackend {
    Socket, // Unix domain socket (default)
    File,   // File-based watching (legacy)
}

impl IpcBackend {
    fn from_env() -> Self {
        match std::env::var("UCX_FAULT_IPC_BACKEND").as_deref() {
            Ok("file") => IpcBackend::File,
            Ok("socket") => IpcBackend::Socket,
            _ => IpcBackend::Socket, // default to socket
        }
    }
}

// initialize tracing subscriber with process context
pub fn init_tracing() {
    use tracing_subscriber::{fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt};

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ucx_fault_injector=info".into()),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_thread_ids(true)
                .with_target(false)
                .with_span_events(FmtSpan::ACTIVE),
        )
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

                    if let Err(e) =
                        writeln!(&*locked_file, "session_{}_pid_{}", session_id, current_pid)
                    {
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
    let span = tracing::info_span!("init", pid = current_pid);
    let _enter = span.enter();

    // parse environment variable configuration FIRST
    let env_config = EnvConfig::from_env();
    debug!("parsed environment configuration: {:?}", env_config);

    // Check if function interception is already initialized using file locking
    let function_intercept_already_initialized = is_already_initialized();

    if !function_intercept_already_initialized {
        info!(version = %version_info(), "UCX fault injector loaded");
        info!("initialization starting");

        // Force initialization of real functions to check symbol loading
        debug!("initializing real UCX function pointers");
        init_real_ucp_get_nbx();
        init_real_ucp_put_nbx();
        init_real_ucp_ep_flush_nbx();

        // Print detailed debug info if debug mode is enabled
        if env_config.debug {
            print_library_debug_info();
        }

        // register atexit handler as backup cleanup mechanism
        unsafe {
            libc::atexit(atexit_cleanup);
        }

        info!("UCX fault injector function interception initialization complete");
    } else {
        info!(
            "UCX fault injector function interception already initialized, skipping function setup"
        );
    }

    // Always initialize local state for each process
    #[cfg(not(test))]
    let _ = &*LOCAL_STATE; // Force Lazy initialization
    #[cfg(test)]
    let _ = &LOCAL_STATE; // Already initialized as static

    // Apply environment variable configuration
    env_config.apply();

    let state = get_current_state();
    info!(
        enabled = state.enabled,
        strategy = %state.strategy,
        probability = state.probability,
        pattern = ?state.pattern,
        error_codes = ?state.error_codes,
        "configuration applied"
    );

    // ONLY start IPC if explicitly enabled via UCX_FAULT_IPC_ENABLE
    if env_config.ipc_enable {
        info!("IPC enabled via UCX_FAULT_IPC_ENABLE");

        // Determine which IPC backend to use
        let ipc_backend = IpcBackend::from_env();

        // Clean up old IPC artifacts based on backend
        match ipc_backend {
            IpcBackend::Socket => {
                // Remove stale socket for this PID
                let socket_path = format!("/tmp/ucx-fault-{}.sock", current_pid);
                if std::path::Path::new(&socket_path).exists() {
                    if let Err(e) = std::fs::remove_file(&socket_path) {
                        warn!(socket_path, error = %e, "failed to remove stale socket");
                    } else {
                        debug!(socket_path, "removed stale socket file");
                    }
                }
            }
            IpcBackend::File => {
                // Clear old command file to prevent replay of stale commands
                let command_file = "/tmp/ucx-fault-commands";
                if std::path::Path::new(command_file).exists() {
                    if let Err(e) = std::fs::remove_file(command_file) {
                        warn!(command_file, error = %e, "failed to clear old command file");
                    } else {
                        debug!(
                            command_file,
                            "cleared old command file to prevent stale command replay"
                        );
                    }
                }
            }
        }

        // Start IPC backend
        match ipc_backend {
            IpcBackend::Socket => {
                info!("starting Unix domain socket server for runtime commands");
                start_socket_server();
                let socket_path = format!("/tmp/ucx-fault-{}.sock", current_pid);
                info!(socket_path, backend = "socket", "IPC server started");

                if !function_intercept_already_initialized {
                    info!("socket-based commands:");
                    info!("  Use ucx-fault-client to send commands via Unix domain sockets");
                    info!("  Examples: ./ucx-fault-client toggle");
                    info!("           ./ucx-fault-client probability 50");
                    info!("           ./ucx-fault-client status");
                }
            }
            IpcBackend::File => {
                info!("starting file watcher for runtime commands");
                start_file_watcher();
                info!(
                    command_file = "/tmp/ucx-fault-commands",
                    backend = "file",
                    "IPC server started"
                );

                if !function_intercept_already_initialized {
                    info!("file-based commands:");
                    info!("  Use ucx-fault-client to send commands via file");
                    info!("  Examples: ./ucx-fault-client toggle");
                    info!("           ./ucx-fault-client probability 50");
                    info!("           ./ucx-fault-client status");
                }
            }
        }
    } else {
        info!("IPC DISABLED (set UCX_FAULT_IPC_ENABLE=1 to enable runtime control)");
        info!("fault injector configured via environment variables only");
        if !function_intercept_already_initialized {
            info!("available environment variables:");
            info!("  UCX_FAULT_ENABLED=1           - enable fault injection at startup");
            info!("  UCX_FAULT_STRATEGY=random     - set strategy (random|pattern)");
            info!("  UCX_FAULT_PROBABILITY=25      - set probability (0.0-100.0) for random");
            info!("  UCX_FAULT_PATTERN=XOOOXOOO    - set pattern for pattern strategy");
            info!("  UCX_FAULT_ERROR_CODES=-3,-6   - comma-separated error codes");
            info!("  UCX_FAULT_HOOKS=ucp_get_nbx   - which hooks to enable (default: all)");
            info!("  UCX_FAULT_IPC_ENABLE=1        - enable runtime control via IPC");
            info!("  UCX_FAULT_DEBUG=1             - enable debug logging");
        }
    }

    info!(
        ipc_enabled = env_config.ipc_enable,
        "UCX fault injector initialization complete"
    );
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
    if CLEANUP_IN_PROGRESS
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
        .is_ok()
    {
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
