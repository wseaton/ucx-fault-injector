use libc::{c_int, c_void};

// UCX types and constants
pub type UcsStatus = c_int;
pub type UcsStatusPtr = *mut c_void;
pub type UcpEpH = *mut c_void;
pub type UcpRkeyH = *mut c_void;
pub type UcpRequestParamT = *const c_void;

// Correct UCX error codes from ucx/src/ucs/type/status.h
pub const UCS_OK: UcsStatus = 0;
pub const UCS_INPROGRESS: UcsStatus = 1;
pub const UCS_ERR_NO_MESSAGE: UcsStatus = -1;
pub const UCS_ERR_NO_RESOURCE: UcsStatus = -2;
pub const UCS_ERR_IO_ERROR: UcsStatus = -3;
pub const UCS_ERR_NO_MEMORY: UcsStatus = -4;
pub const UCS_ERR_INVALID_PARAM: UcsStatus = -5;
pub const UCS_ERR_UNREACHABLE: UcsStatus = -6;
pub const UCS_ERR_INVALID_ADDR: UcsStatus = -7;
pub const UCS_ERR_NOT_IMPLEMENTED: UcsStatus = -8;
pub const UCS_ERR_MESSAGE_TRUNCATED: UcsStatus = -9;
pub const UCS_ERR_NO_PROGRESS: UcsStatus = -10;
pub const UCS_ERR_BUFFER_TOO_SMALL: UcsStatus = -11;
pub const UCS_ERR_NO_ELEM: UcsStatus = -12;
pub const UCS_ERR_SOME_CONNECTS_FAILED: UcsStatus = -13;
pub const UCS_ERR_NO_DEVICE: UcsStatus = -14;
pub const UCS_ERR_BUSY: UcsStatus = -15;
pub const UCS_ERR_CANCELED: UcsStatus = -16;
pub const UCS_ERR_SHMEM_SEGMENT: UcsStatus = -17;
pub const UCS_ERR_ALREADY_EXISTS: UcsStatus = -18;
pub const UCS_ERR_OUT_OF_RANGE: UcsStatus = -19;
pub const UCS_ERR_TIMED_OUT: UcsStatus = -20;
pub const UCS_ERR_EXCEEDS_LIMIT: UcsStatus = -21;
pub const UCS_ERR_UNSUPPORTED: UcsStatus = -22;
pub const UCS_ERR_REJECTED: UcsStatus = -23;
pub const UCS_ERR_NOT_CONNECTED: UcsStatus = -24;
pub const UCS_ERR_CONNECTION_RESET: UcsStatus = -25;

// UCX pointer encoding - simply cast the negative status code to a pointer
// This follows UCS_STATUS_PTR(_status) macro: ((void*)(intptr_t)(_status))
pub fn ucs_status_to_ptr(status: UcsStatus) -> *mut c_void {
    status as isize as *mut c_void
}
