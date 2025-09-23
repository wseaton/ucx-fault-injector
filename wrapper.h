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

// UCX status codes from ucx/src/ucs/type/status.h
#define UCS_OK                         0
#define UCS_INPROGRESS                 1
#define UCS_ERR_NO_MESSAGE            -1
#define UCS_ERR_NO_RESOURCE           -2
#define UCS_ERR_IO_ERROR              -3
#define UCS_ERR_NO_MEMORY             -4
#define UCS_ERR_INVALID_PARAM         -5
#define UCS_ERR_UNREACHABLE           -6
#define UCS_ERR_INVALID_ADDR          -7
#define UCS_ERR_NOT_IMPLEMENTED       -8
#define UCS_ERR_MESSAGE_TRUNCATED     -9
#define UCS_ERR_NO_PROGRESS          -10
#define UCS_ERR_BUFFER_TOO_SMALL     -11
#define UCS_ERR_NO_ELEM              -12
#define UCS_ERR_SOME_CONNECTS_FAILED -13
#define UCS_ERR_NO_DEVICE            -14
#define UCS_ERR_BUSY                 -15
#define UCS_ERR_CANCELED             -16
#define UCS_ERR_SHMEM_SEGMENT        -17
#define UCS_ERR_ALREADY_EXISTS       -18
#define UCS_ERR_OUT_OF_RANGE         -19
#define UCS_ERR_TIMED_OUT            -20
#define UCS_ERR_EXCEEDS_LIMIT        -21
#define UCS_ERR_UNSUPPORTED          -22
#define UCS_ERR_REJECTED             -23
#define UCS_ERR_NOT_CONNECTED        -24
#define UCS_ERR_CONNECTION_RESET     -25

// Stub function declaration if real UCX isn't available
ucs_status_ptr_t ucp_get_nbx(ucp_ep_h ep, void *buffer, size_t count,
                             uint64_t remote_addr, ucp_rkey_h rkey,
                             const ucp_request_param_t *param);
#endif

#endif // UCX_WRAPPER_H