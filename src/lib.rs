pub mod commands;
pub mod init;
pub mod intercept;
pub mod recorder;
pub mod state;
pub mod strategy;
pub mod subscriber;
pub mod ucx;

#[cfg(test)]
mod tests;

// Re-export key types and functions for external use
pub use commands::{Command, Response, State};
pub use init::init_fault_injector;
pub use intercept::ucp_get_nbx;
pub use recorder::{CallRecord, CallRecordBuffer, RecordingSummary, SerializableCallRecord};
pub use strategy::FaultStrategy;
pub use subscriber::{get_current_state, handle_command};
pub use ucx::*;

// The fault injector will be initialized automatically via #[ctor] in production
// Tests can call init_fault_injector() manually if needed
