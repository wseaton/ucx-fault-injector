use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, FnArg, ItemFn, Token, parse::Parse, parse::ParseStream, Result};

struct InterceptorArgs {
    real_fn_static: syn::Expr,
    finder_fn: syn::Expr,
    hook_enabled: syn::Expr,
    calls_counter: syn::Expr,
    faults_counter: syn::Expr,
}

impl Parse for InterceptorArgs {
    fn parse(input: ParseStream) -> Result<Self> {
        let mut real_fn_static = None;
        let mut finder_fn = None;
        let mut hook_enabled = None;
        let mut calls_counter = None;
        let mut faults_counter = None;

        while !input.is_empty() {
            let ident: syn::Ident = input.parse()?;
            input.parse::<Token![=]>()?;

            match ident.to_string().as_str() {
                "real_fn_static" => real_fn_static = Some(input.parse()?),
                "finder_fn" => finder_fn = Some(input.parse()?),
                "hook_enabled" => hook_enabled = Some(input.parse()?),
                "calls_counter" => calls_counter = Some(input.parse()?),
                "faults_counter" => faults_counter = Some(input.parse()?),
                _ => return Err(syn::Error::new(ident.span(), format!("unknown parameter: {}", ident))),
            }

            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }

        Ok(InterceptorArgs {
            real_fn_static: real_fn_static.ok_or_else(|| input.error("missing real_fn_static"))?,
            finder_fn: finder_fn.ok_or_else(|| input.error("missing finder_fn"))?,
            hook_enabled: hook_enabled.ok_or_else(|| input.error("missing hook_enabled"))?,
            calls_counter: calls_counter.ok_or_else(|| input.error("missing calls_counter"))?,
            faults_counter: faults_counter.ok_or_else(|| input.error("missing faults_counter"))?,
        })
    }
}

/// generates a complete UCX function interceptor with all boilerplate
///
/// # Example
/// ```ignore
/// #[ucx_interceptor(
///     real_fn_static = REAL_UCP_GET_NBX,
///     finder_fn = try_find_real_ucp_get_nbx,
///     hook_enabled = LOCAL_STATE.hook_config.ucp_get_nbx_enabled,
///     calls_counter = LOCAL_STATE.ucp_get_nbx_calls,
///     faults_counter = LOCAL_STATE.ucp_get_nbx_faults,
/// )]
/// pub extern "C" fn ucp_get_nbx(
///     ep: UcpEpH,
///     buffer: *mut c_void,
///     count: size_t,
///     remote_addr: u64,
///     rkey: UcpRkeyH,
///     param: UcpRequestParamT
/// ) -> UcsStatusPtr {
///     // build_params logic - constructs CallParams for this call
///     CallParams {
///         function_type: FunctionType::UcpGetNbx,
///         transfer_size: count as u64,
///         remote_addr,
///         endpoint: ep as u64,
///         rkey: rkey as u64,
///     }
/// }
/// ```
#[proc_macro_attribute]
pub fn ucx_interceptor(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as InterceptorArgs);
    let input_fn = parse_macro_input!(input as ItemFn);

    let InterceptorArgs {
        real_fn_static,
        finder_fn,
        hook_enabled,
        calls_counter,
        faults_counter,
    } = args;

    let fn_vis = &input_fn.vis;
    let fn_name = &input_fn.sig.ident;
    let fn_name_str = fn_name.to_string();
    let fn_inputs = &input_fn.sig.inputs;
    let fn_output = &input_fn.sig.output;
    let build_params_body = &input_fn.block;

    // extract parameter names and types for forwarding to real function
    let param_names: Vec<_> = fn_inputs
        .iter()
        .filter_map(|arg| {
            if let FnArg::Typed(pat_type) = arg {
                if let syn::Pat::Ident(pat_ident) = &*pat_type.pat {
                    return Some(&pat_ident.ident);
                }
            }
            None
        })
        .collect();

    let param_types: Vec<_> = fn_inputs
        .iter()
        .filter_map(|arg| {
            if let FnArg::Typed(pat_type) = arg {
                return Some(&pat_type.ty);
            }
            None
        })
        .collect();

    let expanded = quote! {
        #[no_mangle]
        #fn_vis extern "C" fn #fn_name(#fn_inputs) #fn_output {
            const FN_NAME: &str = #fn_name_str;

            // ULTRA-FAST PATH: bypass everything when fault injection is disabled
            if !crate::state::LOCAL_STATE.enabled.load(std::sync::atomic::Ordering::Relaxed) {
                let real_fn_ptr = #real_fn_static.load(std::sync::atomic::Ordering::Relaxed);
                if !real_fn_ptr.is_null() {
                    let real_fn: extern "C" fn(#(#param_types),*) #fn_output =
                        unsafe { std::mem::transmute(real_fn_ptr) };
                    return real_fn(#(#param_names),*);
                }
                // lazy init fallback
                let real_fn_ptr = #finder_fn();
                if !real_fn_ptr.is_null() {
                    #real_fn_static.store(real_fn_ptr, std::sync::atomic::Ordering::Relaxed);
                    let real_fn: extern "C" fn(#(#param_types),*) #fn_output =
                        unsafe { std::mem::transmute(real_fn_ptr) };
                    return real_fn(#(#param_names),*);
                }
            }

            // reentrancy guard
            if crate::state::is_in_intercept() {
                tracing::warn!(
                    pid = std::process::id(),
                    "RECURSION DETECTED: {} called while already intercepting",
                    FN_NAME
                );
                return std::ptr::null_mut(); // UCS_OK
            }

            crate::state::set_in_intercept(true);

            // update statistics
            crate::state::LOCAL_STATE
                .stats.total_calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            #calls_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            // call numbering for logging
            static CALL_COUNT: std::sync::atomic::AtomicU32 =
                std::sync::atomic::AtomicU32::new(0);
            let call_num = CALL_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            // function-specific debug logging
            if crate::state::DEBUG_ENABLED.load(std::sync::atomic::Ordering::Relaxed)
                || call_num < 5
            {
                tracing::trace!(
                    pid = std::process::id(),
                    "{} called #{}",
                    FN_NAME,
                    call_num
                );
                crate::intercept::log_debug_info_if_enabled_internal(call_num);
            }

            // build params and check for fault injection
            let params = #build_params_body;
            if let Some(error_code) = crate::intercept::should_inject_fault_for_hook(&#hook_enabled)
            {
                // fault injection path
                crate::state::LOCAL_STATE
                    .stats.faults_injected
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                #faults_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                crate::state::LOCAL_STATE
                    .stats.calls_since_fault
                    .store(0, std::sync::atomic::Ordering::Relaxed);

                if crate::state::LOCAL_STATE.call_recorder.is_recording_enabled() {
                    tracing::debug!(
                        pid = std::process::id(),
                        "recording fault injection call #{}: error_code={}",
                        call_num,
                        error_code
                    );
                    crate::state::LOCAL_STATE
                        .call_recorder
                        .record_call_with_params(true, error_code, &params);
                }

                tracing::warn!(
                    pid = std::process::id(),
                    error_code = error_code,
                    "[FAULT] INJECTED: {} error ({})",
                    FN_NAME,
                    error_code
                );

                crate::state::set_in_intercept(false);
                return crate::ucx::ucs_status_to_ptr(error_code);
            }

            // successful call path
            if crate::state::LOCAL_STATE.call_recorder.is_recording_enabled() {
                tracing::debug!(
                    pid = std::process::id(),
                    "recording successful call #{}",
                    call_num
                );
                crate::state::LOCAL_STATE
                    .call_recorder
                    .record_call_with_params(false, 0, &params);
            }
            crate::state::LOCAL_STATE
                .stats.calls_since_fault
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            // get real function pointer
            let real_fn_ptr = {
                let mut ptr = #real_fn_static.load(std::sync::atomic::Ordering::Relaxed);
                if ptr.is_null() {
                    ptr = #finder_fn();
                    if !ptr.is_null() {
                        #real_fn_static.store(ptr, std::sync::atomic::Ordering::Relaxed);
                        tracing::debug!(
                            pid = std::process::id(),
                            address = ?ptr,
                            "lazy initialized real {} function",
                            FN_NAME
                        );
                    }
                }
                ptr
            };

            let result = if !real_fn_ptr.is_null() {
                let real_fn: extern "C" fn(#(#param_types),*) #fn_output =
                    unsafe { std::mem::transmute(real_fn_ptr) };

                tracing::trace!(
                    pid = std::process::id(),
                    call_num,
                    address = ?real_fn_ptr,
                    "calling real {} function",
                    FN_NAME
                );
                let result = real_fn(#(#param_names),*);
                tracing::trace!(
                    pid = std::process::id(),
                    call_num,
                    result = ?result,
                    result_int = result as isize,
                    "real {} returned",
                    FN_NAME
                );

                result
            } else {
                tracing::error!(
                    pid = std::process::id(),
                    call_num,
                    "real {} not found, returning IO_ERROR",
                    FN_NAME
                );
                crate::ucx::ucs_status_to_ptr(crate::ucx::UCS_ERR_IO_ERROR)
            };

            crate::state::set_in_intercept(false);
            result
        }
    };

    TokenStream::from(expanded)
}
