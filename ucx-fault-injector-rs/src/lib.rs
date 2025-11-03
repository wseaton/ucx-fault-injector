#![allow(dead_code)]

// module organization
pub mod fault;
pub mod init;
pub mod interception;
pub mod ipc;
pub mod recorder;
pub mod state;
pub mod types;
pub mod ucx;

#[cfg(test)]
mod tests;

// version info from build-time git metadata (similar to setuptools_scm)
pub fn version_info() -> String {
    let cargo_version = env!("CARGO_PKG_VERSION");
    let git_sha = env!("VERGEN_GIT_SHA");
    let git_dirty = env!("VERGEN_GIT_DIRTY");

    if git_dirty == "true" {
        format!("{}-dev+{}.dirty", cargo_version, &git_sha[..7])
    } else {
        format!("{}-dev+{}", cargo_version, &git_sha[..7])
    }
}

// re-export key types and functions for external use
pub use fault::FaultStrategy;
pub use init::init_fault_injector;
pub use interception::ucp_get_nbx;
pub use ipc::{get_current_state, handle_command, Command, Response, State};
pub use recorder::{
    CallParams, CallRecord, CallRecordBuffer, RecordIterator, RecordingSummary,
    SerializableCallRecord,
};
pub use types::{ExportFormat, FaultPattern, HookName, PatternError, Probability};
pub use ucx::*;
