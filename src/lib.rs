pub mod ucx;
pub mod strategy;
pub mod state;
pub mod commands;
pub mod subscriber;
pub mod init;
pub mod intercept;
pub mod recorder;

#[cfg(test)]
mod tests;

// Re-export key types and functions for external use
pub use ucx::*;
pub use strategy::FaultStrategy;
pub use commands::{Command, Response, State};
pub use subscriber::{get_current_state, handle_command};
pub use intercept::ucp_get_nbx;
pub use init::init_fault_injector;
pub use recorder::{CallRecord, CallRecordBuffer, SerializableCallRecord, RecordingSummary};

// The fault injector will be initialized automatically via #[ctor] in production
// Tests can call init_fault_injector() manually if needed











