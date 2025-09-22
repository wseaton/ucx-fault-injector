use libc::{c_void, size_t, c_int};
use once_cell::sync::Lazy;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use nix::fcntl::{flock, FlockArg};
use std::thread;
use serde::{Deserialize, Serialize};

// UCX types and constants
type UcsStatus = c_int;
type UcsStatusPtr = *mut c_void;
type UcpEpH = *mut c_void;
type UcpRkeyH = *mut c_void;
type UcpRequestParamT = *const c_void;

// Correct UCX error codes from ucx/src/ucs/type/status.h
const UCS_ERR_IO_ERROR: UcsStatus = -3;
const UCS_ERR_NO_MEMORY: UcsStatus = -4;
const UCS_ERR_INVALID_PARAM: UcsStatus = -5;
const UCS_ERR_NO_RESOURCE: UcsStatus = -2;
const UCS_ERR_CANCELED: UcsStatus = -16;
const UCS_ERR_UNREACHABLE: UcsStatus = -6;
const UCS_ERR_TIMED_OUT: UcsStatus = -20;

// UCX pointer encoding - simply cast the negative status code to a pointer
// This follows UCS_STATUS_PTR(_status) macro: ((void*)(intptr_t)(_status))
fn ucs_status_to_ptr(status: UcsStatus) -> *mut c_void {
    status as isize as *mut c_void
}

// fault injection state controlled by socket API
static FAULT_ENABLED: AtomicBool = AtomicBool::new(false);
static FAULT_SCENARIO: AtomicU32 = AtomicU32::new(0);
static FAULT_PROBABILITY: AtomicU32 = AtomicU32::new(0); // 0-100
static DEBUG_ENABLED: AtomicBool = AtomicBool::new(false);

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
            match flock(file.as_raw_fd(), FlockArg::LockExclusiveNonblock) {
                Ok(()) => {
                    // We got the lock, write our PID and keep the file open
                    use std::io::Write;

                    if let Err(e) = writeln!(&file, "session_{}_pid_{}", session_id, current_pid) {
                        eprintln!("[ERROR] Failed to write session/PID to lock file: {}", e);
                    }

                    // Store the file descriptor so we keep the lock
                    // In a real implementation, we'd store this somewhere static
                    // For now, we'll leak the file descriptor intentionally
                    std::mem::forget(file);
                    false // Not already initialized
                }
                Err(_) => {
                    // Lock failed, someone else has it
                    true // Already initialized
                }
            }
        }
        Err(e) => {
            eprintln!("[ERROR] Failed to create lock file {}: {}", lock_file_path, e);
            false // Assume not initialized on error
        }
    }
}

// function pointers to real UCX functions
static REAL_FUNCTIONS: Lazy<Mutex<RealFunctions>> = Lazy::new(|| {
    Mutex::new(RealFunctions::new())
});

struct RealFunctions {
    // Only hook ucp_get_nbx for remote reads
    ucp_get_nbx: Option<extern "C" fn(UcpEpH, *mut c_void, size_t, u64, UcpRkeyH, UcpRequestParamT) -> UcsStatusPtr>,
}

impl RealFunctions {
    fn new() -> Self {
        use std::ffi::CString;

        eprintln!("[DEBUG] RealFunctions::new() - Loading original UCX functions...");

        // Try multiple approaches to find the real UCX function
        let ucp_get_nbx = unsafe {
            let symbol_name = CString::new("ucp_get_nbx").unwrap();

            // First try RTLD_NEXT
            eprintln!("[DEBUG] Looking up symbol with RTLD_NEXT: ucp_get_nbx");
            let mut ptr = libc::dlsym(libc::RTLD_NEXT, symbol_name.as_ptr());

            if ptr.is_null() {
                eprintln!("[DEBUG] RTLD_NEXT failed, trying RTLD_DEFAULT");
                ptr = libc::dlsym(libc::RTLD_DEFAULT, symbol_name.as_ptr());
            }

            if ptr.is_null() {
                eprintln!("[DEBUG] RTLD_DEFAULT failed, trying to load UCX libraries directly");
                // Try to find UCX libraries by name patterns
                let ucx_lib_names = [
                    "libucp.so",
                    "libucp.so.0",
                    "/usr/lib64/libucp.so",
                    "/usr/local/lib/libucp.so"
                ];

                for lib_name in &ucx_lib_names {
                    let lib_name_c = CString::new(*lib_name).unwrap();
                    let handle = libc::dlopen(lib_name_c.as_ptr(), libc::RTLD_LAZY);
                    if !handle.is_null() {
                        eprintln!("[DEBUG] Successfully loaded library: {}", lib_name);
                        ptr = libc::dlsym(handle, symbol_name.as_ptr());
                        if !ptr.is_null() {
                            eprintln!("[DEBUG] Found ucp_get_nbx in {}", lib_name);
                            break;
                        }
                    }
                }
            }

            if ptr.is_null() {
                eprintln!("[ERROR] Failed to find ucp_get_nbx symbol via any method");
                let error = libc::dlerror();
                if !error.is_null() {
                    let error_str = std::ffi::CStr::from_ptr(error);
                    eprintln!("[ERROR] dlsym error: {:?}", error_str);
                }

                // As a fallback, create a stub that will be called when real function is not available
                eprintln!("[DEBUG] Creating stub function for ucp_get_nbx");
                Some(Self::stub_ucp_get_nbx as extern "C" fn(UcpEpH, *mut c_void, size_t, u64, UcpRkeyH, UcpRequestParamT) -> UcsStatusPtr)
            } else {
                eprintln!("[DEBUG] Successfully found ucp_get_nbx at address: {:p}", ptr);
                Some(std::mem::transmute::<*mut libc::c_void, extern "C" fn(UcpEpH, *mut c_void, size_t, u64, UcpRkeyH, UcpRequestParamT) -> UcsStatusPtr>(ptr))
            }
        };

        eprintln!("[DEBUG] RealFunctions initialized - ucp_get_nbx: {}",
                 ucp_get_nbx.is_some());

        Self {
            ucp_get_nbx,
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
        eprintln!("[STUB] ucp_get_nbx stub called - returning success");
        std::ptr::null_mut() // UCS_OK represented as null pointer
    }
}

// Socket server functions for fault control
fn get_current_state() -> State {
    State {
        enabled: FAULT_ENABLED.load(Ordering::Relaxed),
        scenario: FAULT_SCENARIO.load(Ordering::Relaxed),
        probability: FAULT_PROBABILITY.load(Ordering::Relaxed),
    }
}

fn handle_command(cmd: Command) -> Response {
    match cmd.command.as_str() {
        "toggle" => {
            let current = FAULT_ENABLED.load(Ordering::Relaxed);
            FAULT_ENABLED.store(!current, Ordering::Relaxed);
            let new_state = !current;
            eprintln!("[SOCKET] UCX Fault Injector: fault injection {}",
                      if new_state { "ENABLED" } else { "DISABLED" });
            Response {
                status: "ok".to_string(),
                message: format!("Fault injection {}", if new_state { "enabled" } else { "disabled" }),
                state: Some(get_current_state()),
            }
        }
        "set_scenario" => {
            if let Some(scenario) = cmd.scenario {
                if scenario <= 2 {
                    FAULT_SCENARIO.store(scenario, Ordering::Relaxed);
                    let scenario_name = match scenario {
                        0 => "NETWORK_ERROR",
                        1 => "TIMEOUT",
                        2 => "MEMORY_ERROR",
                        _ => "UNKNOWN",
                    };
                    eprintln!("[SOCKET] UCX Fault Injector: switched to scenario {}", scenario_name);
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
                    FAULT_PROBABILITY.store(value, Ordering::Relaxed);
                    eprintln!("[SOCKET] UCX Fault Injector: probability set to {}%", value);
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
            FAULT_ENABLED.store(false, Ordering::Relaxed);
            FAULT_SCENARIO.store(0, Ordering::Relaxed);
            FAULT_PROBABILITY.store(10, Ordering::Relaxed);
            eprintln!("[SOCKET] UCX Fault Injector: reset to defaults");
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
            eprintln!("[ZMQ] Failed to connect to {}: {}", broadcast_addr, e);
            return;
        }

        // Subscribe to all messages
        subscriber.set_subscribe(b"").unwrap();

        eprintln!("[ZMQ] Subscriber listening on {} for PID {}", broadcast_addr, std::process::id());

        loop {
            match subscriber.recv_string(0) {
                Ok(Ok(msg)) => {
                    eprintln!("[ZMQ] PID {} received message: {}", std::process::id(), msg);

                    match serde_json::from_str::<Command>(&msg) {
                        Ok(cmd) => {
                            let response = handle_command(cmd);
                            eprintln!("[ZMQ] PID {} processed command: {}", std::process::id(), response.message);
                        }
                        Err(e) => {
                            eprintln!("[ZMQ] Invalid JSON: {}", e);
                        }
                    }
                }
                Ok(Err(e)) => {
                    eprintln!("[ZMQ] UTF-8 decode error: {:?}", e);
                }
                Err(e) => {
                    eprintln!("[ZMQ] Receive error: {}", e);
                    break;
                }
            }
        }
    });
}


// initialize socket server
#[ctor::ctor]
fn init_fault_injector() {
    let current_pid = std::process::id();

    // Check if already initialized using file locking
    if is_already_initialized() {
        eprintln!("[INIT] UCX Fault Injector already initialized for PID: {}, skipping", current_pid);
        return;
    }

    eprintln!("[INIT] UCX Fault Injector loaded (Rust version)");
    eprintln!("[INIT] PID: {}", current_pid);

    // check for debug mode
    if std::env::var("UCX_FAULT_DEBUG").is_ok() {
        DEBUG_ENABLED.store(true, Ordering::Relaxed);
        eprintln!("[INIT] Debug mode enabled via UCX_FAULT_DEBUG environment variable");
    }

    // set default probability
    FAULT_PROBABILITY.store(10, Ordering::Relaxed);
    eprintln!("[INIT] Default fault probability set to 10%");

    // start ZMQ subscriber
    eprintln!("[INIT] Starting ZMQ subscriber...");
    start_zmq_subscriber();
    eprintln!("[INIT] ZMQ subscriber started on tcp://127.0.0.1:15559");

    eprintln!("[INIT] ZMQ broadcast commands:");
    eprintln!("[INIT]   {{\"command\": \"toggle\"}} - toggle fault injection");
    eprintln!("[INIT]   {{\"command\": \"set_scenario\", \"scenario\": 0|1|2}} - set fault scenario");
    eprintln!("[INIT]   {{\"command\": \"set_probability\", \"value\": 0-100}} - set fault probability");
    eprintln!("[INIT]   {{\"command\": \"reset\"}} - reset to defaults");
    eprintln!("[INIT]   {{\"command\": \"status\"}} - get current state");

    // Force initialization of real functions to check symbol loading
    eprintln!("[INIT] Forcing initialization of REAL_FUNCTIONS...");
    let _ = &*REAL_FUNCTIONS;

    // Print detailed debug info if debug mode is enabled
    if DEBUG_ENABLED.load(Ordering::Relaxed) {
        print_library_debug_info();
    }

    eprintln!("[INIT] UCX Fault Injector initialization complete!");
    eprintln!("[INIT] To enable debug output, set UCX_FAULT_DEBUG=1 in environment");
}

// helper function to print debug info about loaded libraries
fn print_library_debug_info() {
    eprintln!("[DEBUG] === Library Debug Information ===");

    // Try to read /proc/self/maps to see loaded libraries
    if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
        eprintln!("[DEBUG] Looking for UCX libraries in process memory map:");
        for line in maps.lines() {
            if line.contains("libucp") || line.contains("libucs") || line.contains("ucx") {
                eprintln!("[DEBUG]   {}", line);
            }
        }
    }

    // Check if we can find UCX symbols using different methods
    unsafe {
        let ucp_put_default = libc::dlsym(libc::RTLD_DEFAULT, b"ucp_put\0".as_ptr() as *const i8);
        let ucp_put_next = libc::dlsym(libc::RTLD_NEXT, b"ucp_put\0".as_ptr() as *const i8);

        eprintln!("[DEBUG] ucp_put via RTLD_DEFAULT: {:p}", ucp_put_default);
        eprintln!("[DEBUG] ucp_put via RTLD_NEXT: {:p}", ucp_put_next);

        let ucp_get_default = libc::dlsym(libc::RTLD_DEFAULT, b"ucp_get\0".as_ptr() as *const i8);
        let ucp_get_next = libc::dlsym(libc::RTLD_NEXT, b"ucp_get\0".as_ptr() as *const i8);

        eprintln!("[DEBUG] ucp_get via RTLD_DEFAULT: {:p}", ucp_get_default);
        eprintln!("[DEBUG] ucp_get via RTLD_NEXT: {:p}", ucp_get_next);
    }

    eprintln!("[DEBUG] === End Library Debug Information ===");
}

// helper function to decide fault injection
fn should_inject_fault() -> bool {
    // Check control file for real-time settings
    let control_file = "/tmp/ucx-fault-control";

    let contents = match std::fs::read_to_string(control_file) {
        Ok(content) => content,
        Err(_) => return false, // No control file = no faults
    };

    let mut enabled = false;
    let mut probability = 0u32;

    for line in contents.lines() {
        if line.starts_with("enabled=") {
            enabled = line.split('=').nth(1).unwrap_or("0") == "1";
        } else if line.starts_with("probability=") {
            probability = line.split('=').nth(1).unwrap_or("0").parse().unwrap_or(0);
        }
    }

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
    // Always log the first few calls to verify hook is working
    static CALL_COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let call_num = CALL_COUNT.fetch_add(1, Ordering::Relaxed);

    if DEBUG_ENABLED.load(Ordering::Relaxed) || call_num < 5 {
        eprintln!("[HOOK] ucp_get_nbx called #{} - ep: {:p}, buffer: {:p}, count: {}, remote_addr: 0x{:x}, rkey: {:p}, param: {:p}",
                 call_num, ep, buffer, count, remote_addr, rkey, param);
        eprintln!("[HOOK] Fault state: enabled={}, scenario={}, probability={}%",
                 FAULT_ENABLED.load(Ordering::Relaxed),
                 FAULT_SCENARIO.load(Ordering::Relaxed),
                 FAULT_PROBABILITY.load(Ordering::Relaxed));
    }

    if should_inject_fault() {
        // Read scenario from control file
        let control_file = "/tmp/ucx-fault-control";
        let mut scenario = 0u32;

        if let Ok(contents) = std::fs::read_to_string(control_file) {
            for line in contents.lines() {
                if line.starts_with("scenario=") {
                    scenario = line.split('=').nth(1).unwrap_or("0").parse().unwrap_or(0);
                    break;
                }
            }
        }
        match scenario {
            0 => {
                eprintln!("[FAULT] INJECTED: ucp_get_nbx network/IO error (UCS_ERR_IO_ERROR = -3)");
                return ucs_status_to_ptr(UCS_ERR_IO_ERROR);
            }
            1 => {
                eprintln!("[FAULT] INJECTED: ucp_get_nbx unreachable error (UCS_ERR_UNREACHABLE = -6)");
                return ucs_status_to_ptr(UCS_ERR_UNREACHABLE);
            }
            2 => {
                eprintln!("[FAULT] INJECTED: ucp_get_nbx timeout error (UCS_ERR_TIMED_OUT = -20)");
                return ucs_status_to_ptr(UCS_ERR_TIMED_OUT);
            }
            _ => {}
        }
    }

    let real_funcs = REAL_FUNCTIONS.lock().unwrap();
    if let Some(real_fn) = real_funcs.ucp_get_nbx {
        if DEBUG_ENABLED.load(Ordering::Relaxed) {
            eprintln!("[HOOK] Calling real ucp_get_nbx function at {:p}", real_fn as *const ());
        }
        let result = real_fn(ep, buffer, count, remote_addr, rkey, param);
        if DEBUG_ENABLED.load(Ordering::Relaxed) {
            eprintln!("[HOOK] Real ucp_get_nbx returned: {:p}", result);
        }
        result
    } else {
        eprintln!("[ERROR] No real ucp_get_nbx function found, returning IO_ERROR");
        ucs_status_to_ptr(UCS_ERR_IO_ERROR)
    }
}