use libc::{c_void, size_t, c_int};
use once_cell::sync::Lazy;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;
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
const UCS_OK: UcsStatus = 0;
const UCS_INPROGRESS: UcsStatus = 1;
const UCS_ERR_NO_MESSAGE: UcsStatus = -1;
const UCS_ERR_NO_RESOURCE: UcsStatus = -2;
const UCS_ERR_IO_ERROR: UcsStatus = -3;
const UCS_ERR_NO_MEMORY: UcsStatus = -4;
const UCS_ERR_INVALID_PARAM: UcsStatus = -5;
const UCS_ERR_UNREACHABLE: UcsStatus = -6;
const UCS_ERR_INVALID_ADDR: UcsStatus = -7;
const UCS_ERR_NOT_IMPLEMENTED: UcsStatus = -8;
const UCS_ERR_MESSAGE_TRUNCATED: UcsStatus = -9;
const UCS_ERR_NO_PROGRESS: UcsStatus = -10;
const UCS_ERR_BUFFER_TOO_SMALL: UcsStatus = -11;
const UCS_ERR_NO_ELEM: UcsStatus = -12;
const UCS_ERR_SOME_CONNECTS_FAILED: UcsStatus = -13;
const UCS_ERR_NO_DEVICE: UcsStatus = -14;
const UCS_ERR_BUSY: UcsStatus = -15;
const UCS_ERR_CANCELED: UcsStatus = -16;
const UCS_ERR_SHMEM_SEGMENT: UcsStatus = -17;
const UCS_ERR_ALREADY_EXISTS: UcsStatus = -18;
const UCS_ERR_OUT_OF_RANGE: UcsStatus = -19;
const UCS_ERR_TIMED_OUT: UcsStatus = -20;
const UCS_ERR_EXCEEDS_LIMIT: UcsStatus = -21;
const UCS_ERR_UNSUPPORTED: UcsStatus = -22;
const UCS_ERR_REJECTED: UcsStatus = -23;
const UCS_ERR_NOT_CONNECTED: UcsStatus = -24;
const UCS_ERR_CONNECTION_RESET: UcsStatus = -25;

// UCX pointer encoding - simply cast the negative status code to a pointer
// This follows UCS_STATUS_PTR(_status) macro: ((void*)(intptr_t)(_status))
fn ucs_status_to_ptr(status: UcsStatus) -> *mut c_void {
    status as isize as *mut c_void
}

#[derive(Debug, Clone, PartialEq)]
enum FaultStrategy {
    Random {
        probability: u32,
        error_codes: Vec<UcsStatus>,
    },
    Pattern {
        pattern: String,
        error_codes: Vec<UcsStatus>,
        current_position: usize,
    },
}

impl FaultStrategy {
    fn new_random(probability: u32) -> Self {
        Self::Random {
            probability,
            error_codes: vec![UCS_ERR_IO_ERROR, UCS_ERR_UNREACHABLE, UCS_ERR_TIMED_OUT],
        }
    }

    fn new_random_with_codes(probability: u32, error_codes: Vec<UcsStatus>) -> Self {
        let codes = if error_codes.is_empty() {
            vec![UCS_ERR_IO_ERROR, UCS_ERR_UNREACHABLE, UCS_ERR_TIMED_OUT]
        } else {
            error_codes
        };
        Self::Random { probability, error_codes: codes }
    }

    fn new_pattern(pattern: String) -> Self {
        Self::Pattern {
            pattern,
            error_codes: vec![UCS_ERR_IO_ERROR, UCS_ERR_UNREACHABLE, UCS_ERR_TIMED_OUT],
            current_position: 0,
        }
    }

    fn new_pattern_with_codes(pattern: String, error_codes: Vec<UcsStatus>) -> Self {
        let codes = if error_codes.is_empty() {
            vec![UCS_ERR_IO_ERROR, UCS_ERR_UNREACHABLE, UCS_ERR_TIMED_OUT]
        } else {
            error_codes
        };
        Self::Pattern {
            pattern,
            error_codes: codes,
            current_position: 0,
        }
    }

    fn should_inject(&mut self) -> Option<UcsStatus> {
        match self {
            Self::Random { probability, error_codes } => {
                if *probability == 0 || error_codes.is_empty() {
                    return None;
                }

                // simple random check
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                use std::time::{SystemTime, UNIX_EPOCH};

                let mut hasher = DefaultHasher::new();
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().hash(&mut hasher);
                let random = (hasher.finish() % 100) as u32;

                if random < *probability {
                    // randomly select an error code from the pool
                    let code_index = (hasher.finish() % error_codes.len() as u64) as usize;
                    Some(error_codes[code_index])
                } else {
                    None
                }
            }
            Self::Pattern { pattern, error_codes, current_position } => {
                if pattern.is_empty() || error_codes.is_empty() {
                    return None;
                }

                let pattern_char = pattern.chars().nth(*current_position % pattern.len()).unwrap_or('O');
                *current_position += 1;

                if pattern_char == 'X' {
                    // cycle through error codes based on position
                    let code_index = (*current_position - 1) % error_codes.len();
                    Some(error_codes[code_index])
                } else {
                    None
                }
            }
        }
    }

    fn set_probability(&mut self, probability: u32) {
        if let Self::Random { probability: ref mut p, .. } = self {
            *p = probability;
        }
    }

    fn set_error_codes(&mut self, codes: Vec<UcsStatus>) {
        let error_codes = if codes.is_empty() {
            vec![UCS_ERR_IO_ERROR, UCS_ERR_UNREACHABLE, UCS_ERR_TIMED_OUT]
        } else {
            codes
        };

        match self {
            Self::Random { error_codes: ref mut ec, .. } => {
                *ec = error_codes;
            }
            Self::Pattern { error_codes: ref mut ec, .. } => {
                *ec = error_codes;
            }
        }
    }


    fn get_probability(&self) -> Option<u32> {
        match self {
            Self::Random { probability, .. } => Some(*probability),
            Self::Pattern { .. } => None,
        }
    }

    fn get_error_codes(&self) -> &[UcsStatus] {
        match self {
            Self::Random { error_codes, .. } => error_codes,
            Self::Pattern { error_codes, .. } => error_codes,
        }
    }

    fn get_pattern(&self) -> Option<&str> {
        match self {
            Self::Random { .. } => None,
            Self::Pattern { pattern, .. } => Some(pattern),
        }
    }

    fn get_strategy_name(&self) -> &'static str {
        match self {
            Self::Random { .. } => "random",
            Self::Pattern { .. } => "pattern",
        }
    }
}

// Local process state structure (no shared memory)
struct LocalFaultState {
    enabled: AtomicBool,
    strategy: Mutex<FaultStrategy>,
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
static LOCAL_STATE: Lazy<LocalFaultState> = Lazy::new(|| {
    info!("initializing local fault injection state");
    LocalFaultState::new()
});

// local debug state (not shared)
static DEBUG_ENABLED: AtomicBool = AtomicBool::new(false);

// reentrancy guard to prevent infinite recursion
thread_local! {
    static IN_INTERCEPT: std::cell::RefCell<bool> = const { std::cell::RefCell::new(false) };
}

// Socket API command and response structures
#[derive(Deserialize)]
struct Command {
    command: String,
    value: Option<u32>,
    pattern: Option<String>,
    error_codes: Option<Vec<i32>>,
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
    probability: u32,
    strategy: String,
    pattern: Option<String>,
    error_codes: Vec<i32>,
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

// function pointers to real UCX functions - use atomic pointer to avoid deadlock
static REAL_UCP_GET_NBX: std::sync::atomic::AtomicPtr<c_void> = std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());


fn try_find_real_ucp_get_nbx() -> *mut c_void {
    use std::ffi::CString;

    debug!("attempting to find real ucp_get_nbx function");

    // Try multiple approaches to find the real UCX function
    unsafe {
        let symbol_name = CString::new("ucp_get_nbx").unwrap();

        // First try RTLD_NEXT - this should work for library interposition
        info!("looking up symbol with RTLD_NEXT: ucp_get_nbx");
        let mut ptr = libc::dlsym(libc::RTLD_NEXT, symbol_name.as_ptr());

        // Check if we got our own function (infinite recursion trap)
        let our_function_addr = ucp_get_nbx as *const () as *mut c_void;
        info!("Our function address: {:?}, RTLD_NEXT returned: {:?}", our_function_addr, ptr);
        if ptr == our_function_addr {
            info!("RTLD_NEXT returned our own function, skipping");
            ptr = std::ptr::null_mut();
        }

        if ptr.is_null() {
            info!("RTLD_NEXT failed, trying RTLD_DEFAULT");
            ptr = libc::dlsym(libc::RTLD_DEFAULT, symbol_name.as_ptr());
            info!("RTLD_DEFAULT returned: {:?}", ptr);

            // Check again for our own function
            if ptr == our_function_addr {
                info!("RTLD_DEFAULT returned our own function, skipping");
                ptr = std::ptr::null_mut();
            }
        }

        if ptr.is_null() {
            info!("RTLD_DEFAULT failed, trying to find UCX libraries in loaded modules");

            // First, try to find where UCX is already loaded by reading memory maps
            let ucx_lib_paths = Vec::new();

            #[cfg(target_os = "linux")]
            {
                if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
                    for line in maps.lines() {
                        if line.contains("libucp") {
                            // Extract the library path from the maps line
                            if let Some(path_start) = line.rfind(' ') {
                                let path = &line[path_start + 1..];
                                if path.starts_with('/') && !ucx_lib_paths.contains(&path.to_string()) {
                                    ucx_lib_paths.push(path.to_string());
                                    info!("Found UCX library in memory map: {}", path);
                                }
                            }
                        }
                    }
                }
            }

            #[cfg(target_os = "macos")]
            {
                // On macOS, we can't easily read memory maps like on Linux
                // Instead, we'll rely on standard search paths
                info!("macOS detected, using standard UCX search paths");
            }

            // Add the found paths to our search list
            let mut ucx_lib_names = ucx_lib_paths;

            // Also try standard locations as fallback
            #[cfg(target_os = "linux")]
            ucx_lib_names.extend([
                "libucp.so".to_string(),
                "libucp.so.0".to_string(),
                "/usr/lib64/libucp.so".to_string(),
                "/usr/local/lib/libucp.so".to_string(),
                "/opt/ucx/lib/libucp.so".to_string(),
            ]);

            #[cfg(target_os = "macos")]
            {
                let home = std::env::var("HOME").unwrap_or_default();
                ucx_lib_names.extend([
                    "libucp.dylib".to_string(),
                    "libucp.0.dylib".to_string(),
                    "/usr/local/lib/libucp.dylib".to_string(),
                    "/opt/homebrew/lib/libucp.dylib".to_string(),
                    format!("{}/ucx/lib/libucp.dylib", home),
                ]);
            }

            for lib_name in &ucx_lib_names {
                info!("Trying to load library: {}", lib_name);
                let lib_name_c = CString::new(lib_name.as_str()).unwrap();
                let handle = libc::dlopen(lib_name_c.as_ptr(), libc::RTLD_LAZY);
                if !handle.is_null() {
                    info!(lib_name, "successfully loaded library");
                    ptr = libc::dlsym(handle, symbol_name.as_ptr());
                    if !ptr.is_null() {
                        info!(lib_name, address = ?ptr, "found ucp_get_nbx");
                        break;
                    } else {
                        info!(lib_name, "library loaded but ucp_get_nbx not found");
                    }
                } else {
                    let error = libc::dlerror();
                    let error_str = if !error.is_null() {
                        std::ffi::CStr::from_ptr(error).to_string_lossy()
                    } else {
                        "unknown error".into()
                    };
                    info!(lib_name, error = %error_str, "failed to load library");
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


// Socket server functions for fault control
fn get_current_state() -> State {
    let strategy = LOCAL_STATE.strategy.lock().unwrap();

    State {
        enabled: LOCAL_STATE.enabled.load(Ordering::Relaxed),
        probability: strategy.get_probability().unwrap_or(0),
        strategy: strategy.get_strategy_name().to_string(),
        pattern: strategy.get_pattern().map(|s| s.to_string()),
        error_codes: strategy.get_error_codes().to_vec(),
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
        "set_probability" => {
            if let Some(value) = cmd.value {
                if value <= 100 {
                    let mut strategy = LOCAL_STATE.strategy.lock().unwrap();
                    strategy.set_probability(value);
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

            // Reset strategy to random with default probability
            let mut strategy = LOCAL_STATE.strategy.lock().unwrap();
            *strategy = FaultStrategy::new_random(25);

            info!("reset to defaults");
            Response {
                status: "ok".to_string(),
                message: "Reset to defaults".to_string(),
                state: Some(get_current_state()),
            }
        }
        "set_strategy" => {
            if let Some(pattern) = cmd.pattern {
                let mut strategy = LOCAL_STATE.strategy.lock().unwrap();
                let error_codes = cmd.error_codes.unwrap_or_default();

                if pattern == "random" {
                    let current_prob = strategy.get_probability().unwrap_or(25);
                    if error_codes.is_empty() {
                        *strategy = FaultStrategy::new_random(current_prob);
                    } else {
                        *strategy = FaultStrategy::new_random_with_codes(current_prob, error_codes);
                    }
                    info!("switched to random fault strategy");
                    Response {
                        status: "ok".to_string(),
                        message: "Strategy set to random".to_string(),
                        state: Some(get_current_state()),
                    }
                } else if !pattern.is_empty() && pattern.chars().all(|c| c == 'X' || c == 'O') {
                    if error_codes.is_empty() {
                        *strategy = FaultStrategy::new_pattern(pattern.clone());
                    } else {
                        *strategy = FaultStrategy::new_pattern_with_codes(pattern.clone(), error_codes);
                    }
                    info!(pattern = %pattern, "switched to pattern fault strategy");
                    Response {
                        status: "ok".to_string(),
                        message: format!("Strategy set to pattern: {}", pattern),
                        state: Some(get_current_state()),
                    }
                } else {
                    Response {
                        status: "error".to_string(),
                        message: "Invalid pattern. Use 'random' or a pattern with only 'X' (fault) and 'O' (pass) characters".to_string(),
                        state: None,
                    }
                }
            } else {
                Response {
                    status: "error".to_string(),
                    message: "Missing pattern parameter".to_string(),
                    state: None,
                }
            }
        }
        "set_error_codes" => {
            if let Some(codes) = cmd.error_codes {
                let mut strategy = LOCAL_STATE.strategy.lock().unwrap();
                strategy.set_error_codes(codes);
                info!(error_codes = ?strategy.get_error_codes(), "error codes updated");
                Response {
                    status: "ok".to_string(),
                    message: format!("Error codes set to: {:?}", strategy.get_error_codes()),
                    state: Some(get_current_state()),
                }
            } else {
                Response {
                    status: "error".to_string(),
                    message: "Missing error_codes parameter".to_string(),
                    state: None,
                }
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

// helper function to decide fault injection using local state
fn should_inject_fault() -> Option<UcsStatus> {
    let enabled = LOCAL_STATE.enabled.load(Ordering::Relaxed);

    if !enabled {
        return None;
    }

    let mut strategy = LOCAL_STATE.strategy.lock().unwrap();
    strategy.should_inject()
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

    if DEBUG_ENABLED.load(Ordering::Relaxed) || call_num < 5 {
        info!(
            "ucp_get_nbx called #{} - ep: {:?}, buffer: {:?}, count: {}, remote_addr: 0x{:x}, rkey: {:?}, param: {:?}",
            call_num, ep, buffer, count, remote_addr, rkey, param
        );

        let state = get_current_state();
        info!(
            "Fault state: enabled={}, strategy={}, pattern={:?}, error_codes={:?}",
            state.enabled, state.strategy, state.pattern, state.error_codes
        );
    }

    if let Some(error_code) = should_inject_fault() {
        warn!(error_code = error_code, "[FAULT] INJECTED: ucp_get_nbx error ({})", error_code);
        let fault_result = ucs_status_to_ptr(error_code);

        // Clear reentrancy guard before returning fault result
        IN_INTERCEPT.with(|flag| {
            *flag.borrow_mut() = false;
        });
        return fault_result;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    // Mock UCX types for testing
    fn create_mock_ep() -> UcpEpH {
        0x1234 as *mut c_void
    }

    fn create_mock_rkey() -> UcpRkeyH {
        0x5678 as *mut c_void
    }

    fn create_mock_param() -> UcpRequestParamT {
        std::ptr::null()
    }

    #[test]
    fn test_fault_strategy_random() {
        let mut strategy = FaultStrategy::new_random(100); // 100% probability
        assert!(strategy.should_inject().is_some());

        let mut strategy = FaultStrategy::new_random(0); // 0% probability
        assert!(strategy.should_inject().is_none());
    }

    #[test]
    fn test_fault_strategy_pattern() {
        let mut strategy = FaultStrategy::new_pattern("XOX".to_string());

        assert!(strategy.should_inject().is_some());  // X
        assert!(strategy.should_inject().is_none()); // O
        assert!(strategy.should_inject().is_some());  // X
        assert!(strategy.should_inject().is_some());  // X (wraps around)
    }

    #[test]
    fn test_command_handling() {
        // Test toggle command
        let cmd = Command {
            command: "toggle".to_string(),
            scenario: None,
            value: None,
            pattern: None,
            error_codes: None,
        };

        let response = handle_command(cmd);
        assert_eq!(response.status, "ok");
        assert!(response.state.is_some());

    }

    #[test]
    fn test_ucp_get_nbx_mock() {
        // Reset state
        LOCAL_STATE.enabled.store(false, Ordering::Relaxed);

        let ep = create_mock_ep();
        let buffer = std::ptr::null_mut();
        let count = 1024;
        let remote_addr = 0x1000;
        let rkey = create_mock_rkey();
        let param = create_mock_param();

        // Test with fault injection disabled - should not inject faults
        let result = ucp_get_nbx(ep, buffer, count, remote_addr, rkey, param);
        // With no real UCX, this will return an error (IO_ERROR)
        assert_eq!(result as isize, UCS_ERR_IO_ERROR as isize);

        // Enable fault injection
        LOCAL_STATE.enabled.store(true, Ordering::Relaxed);

        // Force fault injection with 100% probability and specific error code
        {
            let mut strategy = LOCAL_STATE.strategy.lock().unwrap();
            *strategy = FaultStrategy::new_random_with_codes(100, vec![UCS_ERR_UNREACHABLE]);
        }

        let result = ucp_get_nbx(ep, buffer, count, remote_addr, rkey, param);
        assert_eq!(result as isize, UCS_ERR_UNREACHABLE as isize);
    }

    #[test]
    fn test_status_to_ptr_conversion() {
        let ptr = ucs_status_to_ptr(UCS_ERR_IO_ERROR);
        assert_eq!(ptr as isize, UCS_ERR_IO_ERROR as isize);

        let ptr = ucs_status_to_ptr(UCS_ERR_TIMED_OUT);
        assert_eq!(ptr as isize, UCS_ERR_TIMED_OUT as isize);
    }

    #[test]
    fn test_get_current_state() {
        // Set a known state
        LOCAL_STATE.enabled.store(true, Ordering::Relaxed);

        {
            let mut strategy = LOCAL_STATE.strategy.lock().unwrap();
            *strategy = FaultStrategy::new_random(75);
        }

        let state = get_current_state();
        assert!(state.enabled);
        assert_eq!(state.probability, 75);
        assert_eq!(state.strategy, "random");
        assert!(!state.error_codes.is_empty());
    }

    #[test]
    fn test_error_code_pools() {
        // Test random strategy with custom error codes
        let mut strategy = FaultStrategy::new_random_with_codes(100, vec![UCS_ERR_NO_MEMORY, UCS_ERR_BUSY]);
        for _ in 0..10 {
            if let Some(error_code) = strategy.should_inject() {
                assert!(error_code == UCS_ERR_NO_MEMORY || error_code == UCS_ERR_BUSY);
            }
        }

        // Test pattern strategy with custom error codes
        let mut strategy = FaultStrategy::new_pattern_with_codes("XOX".to_string(), vec![UCS_ERR_CANCELED, UCS_ERR_REJECTED]);
        assert_eq!(strategy.should_inject(), Some(UCS_ERR_CANCELED)); // X
        assert_eq!(strategy.should_inject(), None); // O
        assert_eq!(strategy.should_inject(), Some(UCS_ERR_REJECTED)); // X
        assert_eq!(strategy.should_inject(), Some(UCS_ERR_CANCELED)); // X (wraps around)

        // Test set_error_codes
        strategy.set_error_codes(vec![UCS_ERR_TIMED_OUT]);
        assert_eq!(strategy.should_inject(), None); // O
        assert_eq!(strategy.should_inject(), Some(UCS_ERR_TIMED_OUT)); // X
    }

    #[test]
    fn test_set_error_codes_command() {
        let cmd = Command {
            command: "set_error_codes".to_string(),
            scenario: None,
            value: None,
            pattern: None,
            error_codes: Some(vec![-4, -15]), // UCS_ERR_NO_MEMORY, UCS_ERR_BUSY
        };

        let response = handle_command(cmd);
        assert_eq!(response.status, "ok");
        if let Some(state) = response.state {
            assert_eq!(state.error_codes, vec![-4, -15]);
        }
    }
}
