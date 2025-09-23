#ifndef UCX_WRAPPER_H
#define UCX_WRAPPER_H

#include <stddef.h>
#include <stdint.h>

// UCX includes - try different possible locations
#if __has_include(<ucp/api/ucp.h>)
#include <ucp/api/ucp.h>
#elif __has_include(<ucx/ucp/api/ucp.h>)
#include <ucx/ucp/api/ucp.h>
#elif __has_include(<ucp.h>)
#include <ucp.h>
#endif

#if __has_include(<ucs/type/status.h>)
#include <ucs/type/status.h>
#elif __has_include(<ucx/ucs/type/status.h>)
#include <ucx/ucs/type/status.h>
#elif __has_include(<ucs_status.h>)
#include <ucs_status.h>
#endif

// If UCX headers are not available, provide minimal definitions for compilation
#ifndef UCS_OK
typedef int ucs_status_t;
typedef void* ucs_status_ptr_t;
typedef void* ucp_ep_h;
typedef void* ucp_rkey_h;
typedef void* ucp_request_param_t;

#define UCS_OK                0
#define UCS_ERR_IO_ERROR     -3
#define UCS_ERR_UNREACHABLE  -6
#define UCS_ERR_TIMED_OUT   -20

// Stub function declaration if real UCX isn't available
ucs_status_ptr_t ucp_get_nbx(ucp_ep_h ep, void *buffer, size_t count,
                             uint64_t remote_addr, ucp_rkey_h rkey,
                             const ucp_request_param_t *param);
#endif

#endif // UCX_WRAPPER_H