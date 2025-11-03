use libc::c_void;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicPtr, Ordering};
use tracing::debug;

/// type-safe wrapper around atomic function pointers for UCX interception
///
/// provides lazy initialization, atomic storage, and type-safe calling without
/// repeated unsafe transmute boilerplate throughout the codebase
pub struct UcxFunctionPtr<F> {
    ptr: AtomicPtr<c_void>,
    name: &'static str,
    finder: fn() -> *mut c_void,
    _phantom: PhantomData<F>,
}

impl<F> UcxFunctionPtr<F> {
    pub const fn new(name: &'static str, finder: fn() -> *mut c_void) -> Self {
        Self {
            ptr: AtomicPtr::new(std::ptr::null_mut()),
            name,
            finder,
            _phantom: PhantomData,
        }
    }

    /// eager initialization during library setup (recommended)
    pub fn init(&self) {
        let ptr = (self.finder)();
        self.ptr.store(ptr, Ordering::Relaxed);
        debug!(
            pid = std::process::id(),
            ptr_loaded = !ptr.is_null(),
            "real {} function pointer stored during init",
            self.name
        );
    }

    /// get raw pointer, with lazy initialization fallback
    pub fn get_raw(&self) -> *mut c_void {
        let mut ptr = self.ptr.load(Ordering::Relaxed);

        if ptr.is_null() {
            ptr = (self.finder)();
            if !ptr.is_null() {
                self.ptr.store(ptr, Ordering::Relaxed);
                debug!(
                    pid = std::process::id(),
                    address = ?ptr,
                    "lazy initialized real {} function",
                    self.name
                );
            }
        }

        ptr
    }

    /// ultra-fast path: load without lazy init (assumes pre-initialized)
    #[inline(always)]
    pub fn load_fast(&self) -> *mut c_void {
        self.ptr.load(Ordering::Relaxed)
    }

    /// type-safe call with automatic transmute
    ///
    /// # Safety
    /// caller must ensure F matches the actual function signature
    #[inline(always)]
    pub unsafe fn call<Args, Ret>(&self, args: Args) -> Option<Ret>
    where
        F: FnOnce(Args) -> Ret,
    {
        let ptr = self.get_raw();
        if ptr.is_null() {
            return None;
        }

        // safety: caller guarantees F matches actual signature
        // this is enforced at compile time by the type parameter
        let f: F = std::mem::transmute_copy(&ptr);
        Some(f(args))
    }
}

// safety: atomic pointers are Send + Sync
unsafe impl<F> Send for UcxFunctionPtr<F> {}
unsafe impl<F> Sync for UcxFunctionPtr<F> {}
