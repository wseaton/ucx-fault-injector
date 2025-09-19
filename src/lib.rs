use libc::{c_void, size_t, c_int};
use nix::sys::signal::{self, Signal, SigHandler};
use once_cell::sync::Lazy;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;

// UCX types and constants
type UcsStatus = c_int;
type UcpWorkerH = *mut c_void;
type UcpEpH = *mut c_void;
type UcpEpParams = c_void;
type UcpRkeyH = *mut c_void;

const UCS_OK: UcsStatus = 0;
const UCS_ERR_UNREACHABLE: UcsStatus = -13;
const UCS_ERR_IO_ERROR: UcsStatus = -5;
const UCS_ERR_CANCELED: UcsStatus = -16;

// fault injection state controlled by signals
static FAULT_ENABLED: AtomicBool = AtomicBool::new(false);
static FAULT_SCENARIO: AtomicU32 = AtomicU32::new(0);
static FAULT_PROBABILITY: AtomicU32 = AtomicU32::new(0); // 0-100

// function pointers to real UCX functions
static REAL_FUNCTIONS: Lazy<Mutex<RealFunctions>> = Lazy::new(|| {
    Mutex::new(RealFunctions::new())
});

struct RealFunctions {
    ucp_ep_create: Option<extern "C" fn(UcpWorkerH, *const UcpEpParams, *mut UcpEpH) -> UcsStatus>,
    ucp_put: Option<extern "C" fn(UcpEpH, *const c_void, size_t, u64, UcpRkeyH) -> UcsStatus>,
    ucp_get: Option<extern "C" fn(UcpEpH, *mut c_void, size_t, u64, UcpRkeyH) -> UcsStatus>,
}

impl RealFunctions {
    fn new() -> Self {
        use libloading::{Library, Symbol};

        // attempt to load real UCX functions
        let (ucp_ep_create, ucp_put, ucp_get) = match unsafe { Library::new("libucp.so") } {
            Ok(lib) => {
                let ep_create: Result<Symbol<extern "C" fn(UcpWorkerH, *const UcpEpParams, *mut UcpEpH) -> UcsStatus>, _> =
                    unsafe { lib.get(b"ucp_ep_create") };
                let put: Result<Symbol<extern "C" fn(UcpEpH, *const c_void, size_t, u64, UcpRkeyH) -> UcsStatus>, _> =
                    unsafe { lib.get(b"ucp_put") };
                let get: Result<Symbol<extern "C" fn(UcpEpH, *mut c_void, size_t, u64, UcpRkeyH) -> UcsStatus>, _> =
                    unsafe { lib.get(b"ucp_get") };

                let result = (
                    ep_create.ok().map(|s| *s),
                    put.ok().map(|s| *s),
                    get.ok().map(|s| *s),
                );

                std::mem::forget(lib); // keep library loaded
                result
            }
            Err(_) => (None, None, None),
        };

        Self {
            ucp_ep_create,
            ucp_put,
            ucp_get,
        }
    }
}

// signal handlers for fault control
extern "C" fn handle_sigusr1(_: c_int) {
    let current = FAULT_ENABLED.load(Ordering::Relaxed);
    FAULT_ENABLED.store(!current, Ordering::Relaxed);
    eprintln!("UCX Fault Injector: fault injection {}",
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
    eprintln!("UCX Fault Injector: switched to scenario {}", scenario_name);
}

extern "C" fn handle_increase_probability(_: c_int) {
    let current = FAULT_PROBABILITY.load(Ordering::Relaxed);
    let next = std::cmp::min(current + 10, 100);
    FAULT_PROBABILITY.store(next, Ordering::Relaxed);
    eprintln!("UCX Fault Injector: probability increased to {}%", next);
}

extern "C" fn handle_reset(_: c_int) {
    FAULT_ENABLED.store(false, Ordering::Relaxed);
    FAULT_SCENARIO.store(0, Ordering::Relaxed);
    FAULT_PROBABILITY.store(10, Ordering::Relaxed);
    eprintln!("UCX Fault Injector: reset to defaults");
}

// initialize signal handlers
#[ctor::ctor]
fn init_fault_injector() {
    eprintln!("UCX Fault Injector loaded (Rust version)");

    // set default probability
    FAULT_PROBABILITY.store(10, Ordering::Relaxed);

    // install signal handlers
    unsafe {
        signal::signal(Signal::SIGUSR1, SigHandler::Handler(handle_sigusr1)).unwrap();
        signal::signal(Signal::SIGUSR2, SigHandler::Handler(handle_sigusr2)).unwrap();

        #[cfg(target_os = "linux")]
        {
            // use real-time signals on Linux
            if let Ok(sig) = Signal::try_from(libc::SIGRTMIN + 1) {
                signal::signal(sig, SigHandler::Handler(handle_increase_probability)).unwrap();
            }
            if let Ok(sig) = Signal::try_from(libc::SIGRTMIN + 2) {
                signal::signal(sig, SigHandler::Handler(handle_reset)).unwrap();
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            // fallback signals for non-Linux platforms
            signal::signal(Signal::SIGTERM, SigHandler::Handler(handle_increase_probability)).unwrap();
            signal::signal(Signal::SIGQUIT, SigHandler::Handler(handle_reset)).unwrap();
        }
    }

    eprintln!("Signal handlers installed:");
    eprintln!("  SIGUSR1 - toggle fault injection");
    eprintln!("  SIGUSR2 - cycle fault scenarios");
    #[cfg(target_os = "linux")]
    {
        eprintln!("  SIGRTMIN+1 - increase probability");
        eprintln!("  SIGRTMIN+2 - reset to defaults");
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("  SIGTERM - increase probability");
        eprintln!("  SIGQUIT - reset to defaults");
    }
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

// UCX function interceptors
#[no_mangle]
pub extern "C" fn ucp_ep_create(
    worker: UcpWorkerH,
    params: *const UcpEpParams,
    ep_p: *mut UcpEpH,
) -> UcsStatus {
    if should_inject_fault() {
        eprintln!("FAULT INJECTED: ucp_ep_create failed");
        return UCS_ERR_UNREACHABLE;
    }

    let real_funcs = REAL_FUNCTIONS.lock().unwrap();
    if let Some(real_fn) = real_funcs.ucp_ep_create {
        real_fn(worker, params, ep_p)
    } else {
        UCS_ERR_IO_ERROR
    }
}

#[no_mangle]
pub extern "C" fn ucp_put(
    ep: UcpEpH,
    buffer: *const c_void,
    length: size_t,
    remote_addr: u64,
    rkey: UcpRkeyH,
) -> UcsStatus {
    if should_inject_fault() {
        let scenario = FAULT_SCENARIO.load(Ordering::Relaxed);
        match scenario {
            0 => {
                eprintln!("FAULT INJECTED: ucp_put network error");
                return UCS_ERR_IO_ERROR;
            }
            1 => {
                eprintln!("FAULT INJECTED: ucp_put timeout (5s delay)");
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
            2 => {
                eprintln!("FAULT INJECTED: ucp_put memory error");
                return UCS_ERR_CANCELED;
            }
            _ => {}
        }
    }

    let real_funcs = REAL_FUNCTIONS.lock().unwrap();
    if let Some(real_fn) = real_funcs.ucp_put {
        real_fn(ep, buffer, length, remote_addr, rkey)
    } else {
        UCS_ERR_IO_ERROR
    }
}

#[no_mangle]
pub extern "C" fn ucp_get(
    ep: UcpEpH,
    buffer: *mut c_void,
    length: size_t,
    remote_addr: u64,
    rkey: UcpRkeyH,
) -> UcsStatus {
    if should_inject_fault() {
        eprintln!("FAULT INJECTED: ucp_get failed");
        return UCS_ERR_CANCELED;
    }

    let real_funcs = REAL_FUNCTIONS.lock().unwrap();
    if let Some(real_fn) = real_funcs.ucp_get {
        real_fn(ep, buffer, length, remote_addr, rkey)
    } else {
        UCS_ERR_IO_ERROR
    }
}