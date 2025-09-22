use libc::{c_void, size_t, c_int};
use nix::sys::signal::{self, Signal, SigHandler};
use once_cell::sync::Lazy;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use nix::fcntl::{flock, FlockArg};

// UCX types and constants
type UcsStatus = c_int;
type UcsStatusPtr = *mut c_void;
type UcpEpH = *mut c_void;
type UcpRkeyH = *mut c_void;
type UcpRequestParamT = *const c_void;

const UCS_ERR_IO_ERROR: UcsStatus = -5;
const UCS_ERR_CANCELED: UcsStatus = -16;

// fault injection state controlled by signals
static FAULT_ENABLED: AtomicBool = AtomicBool::new(false);
static FAULT_SCENARIO: AtomicU32 = AtomicU32::new(0);
static FAULT_PROBABILITY: AtomicU32 = AtomicU32::new(0); // 0-100
static DEBUG_ENABLED: AtomicBool = AtomicBool::new(false);


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

        // use dlsym with RTLD_NEXT to find the next version of symbols in the loading order
        let ucp_get_nbx = unsafe {
            let symbol_name = CString::new("ucp_get_nbx").unwrap();
            eprintln!("[DEBUG] Looking up symbol: ucp_get_nbx");
            let ptr = libc::dlsym(libc::RTLD_NEXT, symbol_name.as_ptr());
            if ptr.is_null() {
                eprintln!("[ERROR] Failed to find ucp_get_nbx symbol via dlsym(RTLD_NEXT)");
                let error = unsafe { libc::dlerror() };
                if !error.is_null() {
                    let error_str = unsafe { std::ffi::CStr::from_ptr(error) };
                    eprintln!("[ERROR] dlsym error: {:?}", error_str);
                }
                None
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
}

// signal handlers for fault control
extern "C" fn handle_sigusr1(_: c_int) {
    let current = FAULT_ENABLED.load(Ordering::Relaxed);
    FAULT_ENABLED.store(!current, Ordering::Relaxed);
    eprintln!("[SIGNAL] UCX Fault Injector: fault injection {}",
              if !current { "ENABLED" } else { "DISABLED" });
}

extern "C" fn handle_sigusr2(_: c_int) {
    let current = FAULT_SCENARIO.load(Ordering::Relaxed);
    let next = (current + 1) % 3; // cycle through 3 scenarios
    FAULT_SCENARIO.store(next, Ordering::Relaxed);
    let scenario_name = match next {
        0 => "NETWORK_ERROR",
        1 => "TIMEOUT",
        2 => "MEMORY_ERROR",
        _ => "UNKNOWN",
    };
    eprintln!("[SIGNAL] UCX Fault Injector: switched to scenario {}", scenario_name);
}

extern "C" fn handle_increase_probability(_: c_int) {
    let current = FAULT_PROBABILITY.load(Ordering::Relaxed);
    let next = std::cmp::min(current + 10, 100);
    FAULT_PROBABILITY.store(next, Ordering::Relaxed);
    eprintln!("[SIGNAL] UCX Fault Injector: probability increased to {}%", next);
}

extern "C" fn handle_reset(_: c_int) {
    FAULT_ENABLED.store(false, Ordering::Relaxed);
    FAULT_SCENARIO.store(0, Ordering::Relaxed);
    FAULT_PROBABILITY.store(10, Ordering::Relaxed);
    eprintln!("[SIGNAL] UCX Fault Injector: reset to defaults");
}

// initialize signal handlers
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

    // install signal handlers
    eprintln!("[INIT] Installing signal handlers...");
    unsafe {
        signal::signal(Signal::SIGUSR1, SigHandler::Handler(handle_sigusr1)).unwrap();
        eprintln!("[INIT] SIGUSR1 handler installed");
        signal::signal(Signal::SIGUSR2, SigHandler::Handler(handle_sigusr2)).unwrap();
        eprintln!("[INIT] SIGUSR2 handler installed");

        #[cfg(target_os = "linux")]
        {
            // use real-time signals on Linux
            if let Ok(sig) = Signal::try_from(libc::SIGRTMIN() + 1) {
                signal::signal(sig, SigHandler::Handler(handle_increase_probability)).unwrap();
                eprintln!("[INIT] SIGRTMIN+1 handler installed");
            }
            if let Ok(sig) = Signal::try_from(libc::SIGRTMIN() + 2) {
                signal::signal(sig, SigHandler::Handler(handle_reset)).unwrap();
                eprintln!("[INIT] SIGRTMIN+2 handler installed");
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            // fallback signals for non-Linux platforms
            signal::signal(Signal::SIGTERM, SigHandler::Handler(handle_increase_probability)).unwrap();
            eprintln!("[INIT] SIGTERM handler installed");
            signal::signal(Signal::SIGQUIT, SigHandler::Handler(handle_reset)).unwrap();
            eprintln!("[INIT] SIGQUIT handler installed");
        }
    }

    eprintln!("[INIT] Signal handlers installed:");
    eprintln!("[INIT]   SIGUSR1 - toggle fault injection");
    eprintln!("[INIT]   SIGUSR2 - cycle fault scenarios");
    #[cfg(target_os = "linux")]
    {
        eprintln!("[INIT]   SIGRTMIN+1 - increase probability");
        eprintln!("[INIT]   SIGRTMIN+2 - reset to defaults");
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("[INIT]   SIGTERM - increase probability");
        eprintln!("[INIT]   SIGQUIT - reset to defaults");
    }

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
    if !FAULT_ENABLED.load(Ordering::Relaxed) {
        return false;
    }

    let probability = FAULT_PROBABILITY.load(Ordering::Relaxed);
    if probability == 0 {
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
    if DEBUG_ENABLED.load(Ordering::Relaxed) {
        eprintln!("[HOOK] ucp_get_nbx called - ep: {:p}, buffer: {:p}, count: {}, remote_addr: 0x{:x}, rkey: {:p}, param: {:p}",
                 ep, buffer, count, remote_addr, rkey, param);
    }

    if should_inject_fault() {
        let scenario = FAULT_SCENARIO.load(Ordering::Relaxed);
        match scenario {
            0 => {
                eprintln!("[FAULT] INJECTED: ucp_get_nbx network error");
                // Return error pointer for UCS_ERR_IO_ERROR
                return UCS_ERR_IO_ERROR as isize as *mut c_void;
            }
            1 => {
                eprintln!("[FAULT] INJECTED: ucp_get_nbx timeout (4s delay)");
                std::thread::sleep(std::time::Duration::from_secs(4));
            }
            2 => {
                eprintln!("[FAULT] INJECTED: ucp_get_nbx canceled error");
                // Return error pointer for UCS_ERR_CANCELED
                return UCS_ERR_CANCELED as isize as *mut c_void;
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
        UCS_ERR_IO_ERROR as isize as *mut c_void
    }
}