use libc::{c_void, size_t, c_int};
use once_cell::sync::Lazy;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Mutex, Arc};
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use nix::fcntl::{Flock, FlockArg};
use std::thread;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

// UCX types and constants
type UcsStatus = c_int;
type UcsStatusPtr = *mut c_void;
type UcpEpH = *mut c_void;
type UcpRkeyH = *mut c_void;
type UcpRequestParamT = *const c_void;

// Correct UCX error codes from ucx/src/ucs/type/status.h
const UCS_ERR_IO_ERROR: UcsStatus = -3;
const UCS_ERR_UNREACHABLE: UcsStatus = -6;
const UCS_ERR_TIMED_OUT: UcsStatus = -20;

// UCX pointer encoding - simply cast the negative status code to a pointer
// This follows UCS_STATUS_PTR(_status) macro: ((void*)(intptr_t)(_status))
fn ucs_status_to_ptr(status: UcsStatus) -> *mut c_void {
    status as isize as *mut c_void
}

// Local process state structure (no shared memory)
struct LocalFaultState {
    enabled: AtomicBool,
    scenario: AtomicU32,
    probability: AtomicU32,
}

impl LocalFaultState {
    fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            scenario: AtomicU32::new(0),
            probability: AtomicU32::new(25), // default 25%
        }
    }
}

// Local process state (much safer than shared memory)
static LOCAL_STATE: Lazy<LocalFaultState> = Lazy::new(|| {
    info!("initializing local fault injection state");
    LocalFaultState::new()
});

// local debug state (not shared)
static DEBUG_ENABLED: AtomicBool = AtomicBool::new(false);

// reentrancy guard to prevent infinite recursion
thread_local! {
    static IN_INTERCEPT: std::cell::RefCell<bool> = std::cell::RefCell::new(false);
}

// Socket API command and response structures
#[derive(Deserialize)]
struct Command {
    command: String,
    scenario: Option<u32>,
    value: Option<u32>,
}

#[derive(Serialize)]
struct Response {
    status: String,
    message: String,
    state: Option<State>,
}

#[derive(Serialize)]
struct State {
    enabled: bool,
    scenario: u32,
    probability: u32,
}


// helper function to check if injector is already initialized for this process tree
fn is_already_initialized() -> bool {
    let current_pid = std::process::id();

    // Use session ID to prevent reinitialization across fork/exec in same session
    let session_id = unsafe { libc::getsid(0) };
    let lock_file_path = format!("/tmp/ucx-fault-injector-session-{}.lock", session_id);

    // Try to open and lock the file
    match OpenOptions::new()
        .create(true)
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

// function pointers to real UCX functions - use atomic pointer to avoid deadlock
static REAL_UCP_GET_NBX: std::sync::atomic::AtomicPtr<c_void> = std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

struct RealFunctions {
    // Only hook ucp_get_nbx for remote reads
    ucp_get_nbx: Option<extern "C" fn(UcpEpH, *mut c_void, size_t, u64, UcpRkeyH, UcpRequestParamT) -> UcsStatusPtr>,
}

fn try_find_real_ucp_get_nbx() -> *mut c_void {
    use std::ffi::CString;

    debug!("attempting to find real ucp_get_nbx function");

    // Try multiple approaches to find the real UCX function
    unsafe {
        let symbol_name = CString::new("ucp_get_nbx").unwrap();

        // First try RTLD_NEXT - this should work for library interposition
        debug!("looking up symbol with RTLD_NEXT: ucp_get_nbx");
        let mut ptr = libc::dlsym(libc::RTLD_NEXT, symbol_name.as_ptr());

        // Check if we got our own function (infinite recursion trap)
        let our_function_addr = ucp_get_nbx as *const () as *mut c_void;
        if ptr == our_function_addr {
            debug!("RTLD_NEXT returned our own function, skipping");
            ptr = std::ptr::null_mut();
        }

        if ptr.is_null() {
            debug!("RTLD_NEXT failed, trying RTLD_DEFAULT");
            ptr = libc::dlsym(libc::RTLD_DEFAULT, symbol_name.as_ptr());

            // Check again for our own function
            if ptr == our_function_addr {
                debug!("RTLD_DEFAULT returned our own function, skipping");
                ptr = std::ptr::null_mut();
            }
        }

        if ptr.is_null() {
            debug!("RTLD_DEFAULT failed, trying to load UCX libraries directly");
            // Try to find UCX libraries by name patterns
            let ucx_lib_names = [
                "libucp.so",
                "libucp.so.0",
                "/usr/lib64/libucp.so",
                "/usr/local/lib/libucp.so",
                "/opt/ucx/lib/libucp.so",
                "libucp.dylib", // macOS
            ];

            for lib_name in &ucx_lib_names {
                let lib_name_c = CString::new(*lib_name).unwrap();
                let handle = libc::dlopen(lib_name_c.as_ptr(), libc::RTLD_LAZY);
                if !handle.is_null() {
                    debug!(lib_name, "successfully loaded library");
                    ptr = libc::dlsym(handle, symbol_name.as_ptr());
                    if !ptr.is_null() {
                        debug!(lib_name, "found ucp_get_nbx");
                        break;
                    }
                }
            }
        }

        if ptr.is_null() {
            debug!("failed to find ucp_get_nbx symbol via any method");
            let error = libc::dlerror();
            if !error.is_null() {
                let error_str = std::ffi::CStr::from_ptr(error);
                debug!(error = ?error_str, "dlsym error");
            }
        } else {
            debug!(address = ?ptr, "successfully found ucp_get_nbx");
        }

        ptr
    }
}

fn init_real_ucp_get_nbx() {
    let ptr = try_find_real_ucp_get_nbx();
    REAL_UCP_GET_NBX.store(ptr, std::sync::atomic::Ordering::Relaxed);
    debug!(ptr_loaded = !ptr.is_null(), "real UCX function pointer stored during init");
}

impl RealFunctions {
    fn new() -> Self {
        // This is kept for backward compatibility but won't be used
        Self {
            ucp_get_nbx: None,
        }
    }

    // Stub function that returns success when no real UCX function is available
    extern "C" fn stub_ucp_get_nbx(
        _ep: UcpEpH,
        _buffer: *mut c_void,
        _count: size_t,
        _remote_addr: u64,
        _rkey: UcpRkeyH,
        _param: UcpRequestParamT,
    ) -> UcsStatusPtr {
        debug!("ucp_get_nbx stub called - returning success");
        std::ptr::null_mut() // UCS_OK represented as null pointer
    }
}

// Socket server functions for fault control
fn get_current_state() -> State {
    State {
        enabled: LOCAL_STATE.enabled.load(Ordering::Relaxed),
        scenario: LOCAL_STATE.scenario.load(Ordering::Relaxed),
        probability: LOCAL_STATE.probability.load(Ordering::Relaxed),
    }
}

fn handle_command(cmd: Command) -> Response {
    match cmd.command.as_str() {
        "toggle" => {
            let current = LOCAL_STATE.enabled.load(Ordering::Relaxed);
            let new_state = !current;
            LOCAL_STATE.enabled.store(new_state, Ordering::Relaxed);
            info!(enabled = new_state, "fault injection toggled");
            Response {
                status: "ok".to_string(),
                message: format!("Fault injection {}", if new_state { "enabled" } else { "disabled" }),
                state: Some(get_current_state()),
            }
        }
        "set_scenario" => {
            if let Some(scenario) = cmd.scenario {
                if scenario <= 2 {
                    LOCAL_STATE.scenario.store(scenario, Ordering::Relaxed);
                    let scenario_name = match scenario {
                        0 => "NETWORK_ERROR",
                        1 => "UNREACHABLE_ERROR",
                        2 => "TIMEOUT_ERROR",
                        _ => "UNKNOWN",
                    };
                    info!(scenario = scenario, scenario_name, "switched to scenario");
                    Response {
                        status: "ok".to_string(),
                        message: format!("Scenario set to {} ({})", scenario, scenario_name),
                        state: Some(get_current_state()),
                    }
                } else {
                    Response {
                        status: "error".to_string(),
                        message: "Invalid scenario. Must be 0, 1, or 2".to_string(),
                        state: None,
                    }
                }
            } else {
                Response {
                    status: "error".to_string(),
                    message: "Missing scenario parameter".to_string(),
                    state: None,
                }
            }
        }
        "set_probability" => {
            if let Some(value) = cmd.value {
                if value <= 100 {
                    LOCAL_STATE.probability.store(value, Ordering::Relaxed);
                    info!(probability = value, "probability set");
                    Response {
                        status: "ok".to_string(),
                        message: format!("Probability set to {}%", value),
                        state: Some(get_current_state()),
                    }
                } else {
                    Response {
                        status: "error".to_string(),
                        message: "Invalid probability. Must be 0-100".to_string(),
                        state: None,
                    }
                }
            } else {
                Response {
                    status: "error".to_string(),
                    message: "Missing value parameter".to_string(),
                    state: None,
                }
            }
        }
        "reset" => {
            LOCAL_STATE.enabled.store(false, Ordering::Relaxed);
            LOCAL_STATE.scenario.store(0, Ordering::Relaxed);
            LOCAL_STATE.probability.store(10, Ordering::Relaxed);
            info!("reset to defaults");
            Response {
                status: "ok".to_string(),
                message: "Reset to defaults".to_string(),
                state: Some(get_current_state()),
            }
        }
        "status" => {
            Response {
                status: "ok".to_string(),
                message: "Current state".to_string(),
                state: Some(get_current_state()),
            }
        }
        _ => {
            Response {
                status: "error".to_string(),
                message: format!("Unknown command: {}", cmd.command),
                state: None,
            }
        }
    }
}

fn start_zmq_subscriber() {
    thread::spawn(move || {
        let ctx = zmq::Context::new();
        let subscriber = ctx.socket(zmq::SUB).unwrap();

        // Connect to the broadcast port
        let broadcast_addr = "tcp://127.0.0.1:15559";
        if let Err(e) = subscriber.connect(broadcast_addr) {
            error!(broadcast_addr, error = %e, "failed to connect");
            return;
        }

        // Subscribe to all messages
        subscriber.set_subscribe(b"").unwrap();

        info!(broadcast_addr, pid = std::process::id(), "subscriber listening");

        loop {
            match subscriber.recv_string(0) {
                Ok(Ok(msg)) => {
                    debug!(pid = std::process::id(), message = %msg, "received message");

                    match serde_json::from_str::<Command>(&msg) {
                        Ok(cmd) => {
                            let response = handle_command(cmd);
                            debug!(pid = std::process::id(), response = %response.message, "processed command");
                        }
                        Err(e) => {
                            warn!(error = %e, "invalid JSON");
                        }
                    }
                }
                Ok(Err(e)) => {
                    error!(error = ?e, "UTF-8 decode error");
                }
                Err(e) => {
                    error!(error = %e, "receive error");
                    break;
                }
            }
        }
    });
}


// initialize tracing subscriber
fn init_tracing() {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ucx_fault_injector=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}

// initialize socket server
#[ctor::ctor]
fn init_fault_injector() {
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
    info!(
        enabled = LOCAL_STATE.enabled.load(Ordering::Relaxed),
        scenario = LOCAL_STATE.scenario.load(Ordering::Relaxed),
        probability = LOCAL_STATE.probability.load(Ordering::Relaxed),
        "local process state initialized"
    );

    // start ZMQ subscriber
    info!("starting ZMQ subscriber");
    start_zmq_subscriber();
    info!(address = "tcp://127.0.0.1:15559", "ZMQ subscriber started");

    info!("ZMQ broadcast commands:");
    info!("  {{\"command\": \"toggle\"}} - toggle fault injection");
    info!("  {{\"command\": \"set_scenario\", \"scenario\": 0|1|2}} - set fault scenario");
    info!("  {{\"command\": \"set_probability\", \"value\": 0-100}} - set fault probability");
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

// helper function to print debug info about loaded libraries
fn print_library_debug_info() {
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
        let ucp_put_default = libc::dlsym(libc::RTLD_DEFAULT, b"ucp_put\0".as_ptr() as *const i8);
        let ucp_put_next = libc::dlsym(libc::RTLD_NEXT, b"ucp_put\0".as_ptr() as *const i8);

        debug!(address = ?ucp_put_default, "ucp_put via RTLD_DEFAULT");
        debug!(address = ?ucp_put_next, "ucp_put via RTLD_NEXT");

        let ucp_get_default = libc::dlsym(libc::RTLD_DEFAULT, b"ucp_get\0".as_ptr() as *const i8);
        let ucp_get_next = libc::dlsym(libc::RTLD_NEXT, b"ucp_get\0".as_ptr() as *const i8);

        debug!(address = ?ucp_get_default, "ucp_get via RTLD_DEFAULT");
        debug!(address = ?ucp_get_next, "ucp_get via RTLD_NEXT");
    }

    debug!("=== end library debug information ===");
}

// helper function to decide fault injection using local state
fn should_inject_fault() -> bool {
    let enabled = LOCAL_STATE.enabled.load(Ordering::Relaxed);
    let probability = LOCAL_STATE.probability.load(Ordering::Relaxed);

    if !enabled || probability == 0 {
        return false;
    }

    // simple random check
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut hasher = DefaultHasher::new();
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().hash(&mut hasher);
    let random = (hasher.finish() % 100) as u32;

    random < probability
}

// helper function to decide fault injection using pre-read state
fn should_inject_fault_with_state(state: (bool, u32, u32)) -> bool {
    let (enabled, _scenario, probability) = state;

    if !enabled || probability == 0 {
        return false;
    }

    // simple random check
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut hasher = DefaultHasher::new();
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().hash(&mut hasher);
    let random = (hasher.finish() % 100) as u32;

    random < probability
}

// UCX function interceptors - focused on ucp_get_nbx for remote reads
#[no_mangle]
pub extern "C" fn ucp_get_nbx(
    ep: UcpEpH,
    buffer: *mut c_void,
    count: size_t,
    remote_addr: u64,
    rkey: UcpRkeyH,
    param: UcpRequestParamT,
) -> UcsStatusPtr {
    // Check reentrancy guard to prevent infinite recursion
    let already_in_intercept = IN_INTERCEPT.with(|flag| {
        *flag.borrow()
    });

    if already_in_intercept {
        // We're being called recursively - this shouldn't happen if we resolve correctly
        // but as a safety fallback, return success to avoid infinite recursion
        warn!("RECURSION DETECTED: ucp_get_nbx called while already intercepting");
        return std::ptr::null_mut(); // UCS_OK
    }

    // Set reentrancy guard
    IN_INTERCEPT.with(|flag| {
        *flag.borrow_mut() = true;
    });

    // Always log the first few calls to verify hook is working
    static CALL_COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let call_num = CALL_COUNT.fetch_add(1, Ordering::Relaxed);

    // Read current state once for both logging and fault injection
    let current_state = (
        LOCAL_STATE.enabled.load(Ordering::Relaxed),
        LOCAL_STATE.scenario.load(Ordering::Relaxed),
        LOCAL_STATE.probability.load(Ordering::Relaxed),
    );

    if DEBUG_ENABLED.load(Ordering::Relaxed) || call_num < 5 {
        info!(
            "ucp_get_nbx called #{} - ep: {:?}, buffer: {:?}, count: {}, remote_addr: 0x{:x}, rkey: {:?}, param: {:?}",
            call_num, ep, buffer, count, remote_addr, rkey, param
        );
        info!(
            "Fault state: enabled={}, scenario={}, probability={}%",
            current_state.0, current_state.1, current_state.2
        );
    }

    if should_inject_fault_with_state(current_state) {
        let scenario = current_state.1;
        let fault_result = match scenario {
            0 => {
                warn!(error_code = UCS_ERR_IO_ERROR, "[FAULT] INJECTED: ucp_get_nbx network/IO error (UCS_ERR_IO_ERROR = {})", UCS_ERR_IO_ERROR);
                ucs_status_to_ptr(UCS_ERR_IO_ERROR)
            }
            1 => {
                warn!(error_code = UCS_ERR_UNREACHABLE, "[FAULT] INJECTED: ucp_get_nbx unreachable error (UCS_ERR_UNREACHABLE = {})", UCS_ERR_UNREACHABLE);
                ucs_status_to_ptr(UCS_ERR_UNREACHABLE)
            }
            2 => {
                warn!(error_code = UCS_ERR_TIMED_OUT, "[FAULT] INJECTED: ucp_get_nbx timeout error (UCS_ERR_TIMED_OUT = {})", UCS_ERR_TIMED_OUT);
                ucs_status_to_ptr(UCS_ERR_TIMED_OUT)
            }
            _ => {
                // This case shouldn't happen, continue with normal execution
                std::ptr::null_mut()
            }
        };

        if scenario <= 2 {
            // Clear reentrancy guard before returning fault result
            IN_INTERCEPT.with(|flag| {
                *flag.borrow_mut() = false;
            });
            return fault_result;
        }
    }

    // Get the real function pointer atomically - with lazy initialization
    let mut real_fn_ptr = REAL_UCP_GET_NBX.load(std::sync::atomic::Ordering::Relaxed);

    // If not initialized yet, try to initialize it now
    if real_fn_ptr.is_null() {
        real_fn_ptr = try_find_real_ucp_get_nbx();
        if !real_fn_ptr.is_null() {
            REAL_UCP_GET_NBX.store(real_fn_ptr, std::sync::atomic::Ordering::Relaxed);
            debug!(address = ?real_fn_ptr, "lazy initialized real ucp_get_nbx function");
        }
    }

    let result = if !real_fn_ptr.is_null() {
        // Cast to function pointer and call
        let real_fn: extern "C" fn(UcpEpH, *mut c_void, size_t, u64, UcpRkeyH, UcpRequestParamT) -> UcsStatusPtr =
            unsafe { std::mem::transmute(real_fn_ptr) };

        info!(call_num, address = ?real_fn_ptr, "calling real ucp_get_nbx function");
        let result = real_fn(ep, buffer, count, remote_addr, rkey, param);
        info!(call_num, result = ?result, result_int = result as isize, "real ucp_get_nbx returned");

        // Skip buffer access for now to avoid segfault - UCX operations are async
        result
    } else {
        // Can't find real function - return error since we can't perform the operation
        error!(call_num, "real ucp_get_nbx not found, returning IO_ERROR since operation cannot be completed");
        ucs_status_to_ptr(UCS_ERR_IO_ERROR) // Return error instead of fake success
    };

    // Clear reentrancy guard before returning
    IN_INTERCEPT.with(|flag| {
        *flag.borrow_mut() = false;
    });

    result
}
